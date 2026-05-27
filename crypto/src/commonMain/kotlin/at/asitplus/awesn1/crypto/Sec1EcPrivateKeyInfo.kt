// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.PemLabelSpec
import at.asitplus.awesn1.WithPemLabel
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.awesn1.serialization.ExplicitlyTagged
import at.asitplus.awesn1.serialization.getValue
import at.asitplus.awesn1.toInt
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
/**
 *
 * As per [RFC5915](https://www.rfc-editor.org/rfc/rfc5915.html#section-3):
 * ```
 * ECPrivateKey ::= SEQUENCE {
 *   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
 *   privateKey     OCTET STRING,
 *   parameters [0] ECParameters OPTIONAL,
 *   publicKey  [1] BIT STRING OPTIONAL
 * }
 * ```
 *
 * (See also [errata](https://www.rfc-editor.org/errata/rfc5915)
 */
@ConsistentCopyVisibility
@Serializable
//CTOR internal for testing
data class Sec1EcPrivateKeyInfo internal constructor(
    val version: Version,
    val privateKey: ByteArray,
    @Asn1Tag(tagNumber = 0u)
    private val taggedParameters: ExplicitlyTagged<ObjectIdentifier>? = null,
    @Asn1Tag(tagNumber = 1u)
    private val taggedPublicKey: ExplicitlyTagged<Asn1BitString>? = null,
) : WithPemLabel {

    constructor(
        version: Version = Version.V1,
        privateKey: ByteArray,
        parameters: ObjectIdentifier?,
        publicKey: Asn1BitString?,
    ) : this(
        version = Version.V1,
        privateKey = privateKey,
        taggedParameters = parameters?.let(::ExplicitlyTagged),
        taggedPublicKey = publicKey?.let(::ExplicitlyTagged),
    )
    override val pemLabel: String get() = PEM_LABEL

    init {
        taggedPublicKey?.value?.let {
            if (it.numPaddingBits != 0.toByte()) {
                throw Asn1Exception("Public key value must not have padding bits")
            }
        }
    }

    val parameters: ObjectIdentifier? by taggedParameters

    val publicKey: Asn1BitString? by taggedPublicKey

    override fun equals(other: Any?): Boolean =
        other is Sec1EcPrivateKeyInfo &&
                version == other.version &&
                privateKey.contentEquals(other.privateKey) &&
                taggedParameters == other.taggedParameters &&
                taggedPublicKey == other.taggedPublicKey

    override fun hashCode(): Int {
        var result = version.hashCode()
        result = 31 * result + privateKey.contentHashCode()
        result = 31 * result + (taggedParameters?.hashCode() ?: 0)
        result = 31 * result + (taggedPublicKey?.hashCode() ?: 0)
        return result
    }

    override fun toString(): String {
        return "Sec1EcPrivateKeyInfo(" +
                "rawVersion=$version, " +
                "privateKey=${privateKey.contentToString()}, " +
                "version=$version, " +
                "parameters=$parameters, " +
                "publicKey=$publicKey" +
                ")"
    }

    companion object : PemLabelSpec<Sec1EcPrivateKeyInfo> {
        const val PEM_LABEL = "EC PRIVATE KEY"
        override val canonicalPemLabel: String get() = PEM_LABEL

    }

    /**
     * | Encoded Version | Semantic Version |
     * |:---------------:|:----------------:|
     * | 1               | V1                |
     */

    @Serializable(with = Version.Serializer::class)
    enum class Version {
        V1;

        object Serializer : KSerializer<Version> {
            override val descriptor: SerialDescriptor =
                PrimitiveSerialDescriptor("Sec1EcPrivateKeyInfo.Version", PrimitiveKind.INT)

            override fun serialize(
                encoder: Encoder,
                value: Version
            ) {
                encoder.encodeInt(
                    when(value) {
                        V1 -> 1
                    }

                )
            }

            override fun deserialize(decoder: Decoder): Version {
                when (val intValue = decoder.decodeInt()) {
                    1 -> return V1
                    else -> throw IllegalArgumentException("Invalid version: $intValue")
                }
            }
        }
    }
}
