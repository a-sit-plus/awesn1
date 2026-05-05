// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.parse
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor

/**
 * Explicit-tag modelling wrapper.
 *
 * This wrapper requires an effective implicit tag override resolving to
 * CONTEXT-SPECIFIC + CONSTRUCTED. Missing/invalid configuration is rejected
 * at runtime by the DER serializer/decoder.
 */
@Serializable
data class ExplicitlyTagged<T>(
    val value: T,
) {
    operator fun getValue(thisRef: Any?, property: Any?): T = value
}

operator fun <T> ExplicitlyTagged<T>?.getValue(thisRef: Any?, property: Any?): T? = this?.value


/** Use like so: `val foo by explicitlyTaggedProperty.orValue("Some sane default that must not even align on nullability")`
 */
fun <T> ExplicitlyTagged<T>?.orValue(default: T): ExplicitlyTagged<T> =
    ExplicitlyTagged(this?.value ?: default)

/**
 * OCTET STRING encapsulation wrapper.
 *
 * This is encoded as UNIVERSAL OCTET STRING with primitive form and the
 * encoded payload value bytes as content.
 */
@Serializable
@Asn1Tag(
    tagNumber = 4u,
    tagClass = Asn1Tag.Class.UNIVERSAL,
    constructed = Asn1Tag.ConstructedBit.PRIMITIVE,
)
data class OctetStringEncapsulated<T>(
    val value: T,
)

private const val ExplicitlyTaggedSerialName =
    "at.asitplus.awesn1.serialization.ExplicitlyTagged"

internal fun SerialDescriptor.isAsn1ExplicitWrapperDescriptor(): Boolean =
    serialName.removeSuffix("?").substringBefore('<').let { rawName -> rawName == ExplicitlyTaggedSerialName }


/** Helper interface for encoding to simple PEM structures, where the payload should just be the DER bytes */
interface KxsPemEncodable<T> : PemEncodable {

    fun buildPemHeaders(): Iterable<PemHeader> = emptyList()

    val serializer: KSerializer<T>

    @Throws(IllegalArgumentException::class)
    override fun encodeToPemBlock(): PemBlock =
        runWrappingAs(a = ::IllegalArgumentException) {
            PemBlock(label, buildPemHeaders(), DER.encodeToByteArray(serializer, this as T))
        }
}

/**
 * Helper class for decoding simple PEM structures, where the payload is just the DER bytes.
 * By default, does not allow PEM headers, matching the RFC 7468 structures.
 * Override [decodeFromTlvWithPemHeaders] to customize this.
 */
interface KxsPemDecodable<T>
    : PemDecodable<T> {
    val serializer: KSerializer<T>

    fun decodeFromTlvWithPemHeaders(pemHeaders: Iterable<PemHeader>, tlv: Asn1Element): T =
        runWrappingAs(a = ::IllegalArgumentException) {
            if (pemHeaders.any()) throw IllegalArgumentException("Unexpected PEM headers are present in the data")
            return (DER.decodeFromTlv(serializer, tlv))
        }

    @Throws(IllegalArgumentException::class)
    override fun decodeFromPemBlock(src: PemBlock): T = runWrappingAs(a = ::IllegalArgumentException) {
        validPemLabels?.let { require(src.label in it) { "PEM label is ${src.label}, expected one of ${it.joinToString { it }}" } }
        decodeFromDerWithPemHeaders(src.headers, src.payload)
    }
}

fun <T> KxsPemDecodable<T>.decodeFromDerWithPemHeaders(pemHeaders: Iterable<PemHeader>, der: ByteArray) =
    @Suppress("UNCHECKED_CAST")
    decodeFromTlvWithPemHeaders(pemHeaders, Asn1Element.parse(der))
