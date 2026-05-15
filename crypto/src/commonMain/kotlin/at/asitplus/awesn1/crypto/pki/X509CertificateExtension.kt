// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.serialization.Asn1Tag
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

/**
 *
 * As per [RFC5280](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1):
 * ```
 * Extension  ::=  SEQUENCE  {
 *   extnID      OBJECT IDENTIFIER,
 *   critical    BOOLEAN DEFAULT FALSE,
 *   extnValue   OCTET STRING
 *               -- contains the DER encoding of an ASN.1 value
 *               -- corresponding to the extension type identified
 *               -- by extnID
 * }
 * ```
 */
@Serializable
data class X509CertificateExtension private constructor(
    override val oid: ObjectIdentifier,
    /** Some production certificates have illegal boolean encoding, as in: correct tag, correct length, containing a single byte that is neither `0x00` nor `0xFF`.
     * [X509CertificateExtension] treats those as follows:
     *
     * * `0x00` -> `FALSE`
     * * absent -> `null`
     * * anything else -> `TRUE`
     *
     * Not calling out any names here, but if you can ship literal billions of smartphones, you should be able to comprehend DER encodings of booleans. **You know who you are!**
     *
     * See also [encoding flaws documented by Warden Supreme](https://a-sit-plus.github.io/warden-supreme/technical/quirks/#encoding-flaws).
     * */
    @Asn1Tag(0x01u, tagClass = Asn1Tag.Class.UNIVERSAL)
    val rawCritical: Byte? = null,
    val value: ByteArray,
) : Identifiable {

    constructor(
        oid: ObjectIdentifier,
        critical: Boolean = false,
        value: ByteArray,
    ) : this(oid, if(critical) 0xff.toByte() else null, value)

    constructor(
        oid: ObjectIdentifier,
        critical: Boolean = false,
        value: Asn1EncapsulatingOctetString,
    ) : this(oid, critical, value.content)

    constructor(
        oid: ObjectIdentifier,
        critical: Boolean = false,
        value: Asn1PrimitiveOctetString,
    ) : this(oid, critical, value.content)

    /**
     * Sensible interpretation of [rawCritical], keeping raw nullability, meaning this has three valid values:
     * 1. `null` if absent, meaning non-critical. This is legal
     * 2. `false` if `0x00` was encoded, meaning non-critical. This is illegal because the value should be absent but happens in practice, and we want to preserve it.
     * 3. `true` if in `0x01`..`0xFF`. Anything but `0xff` is illegal but still happens in practice, and this transformation makes it easy to work with
     */

    val critical: Boolean? by lazy {
        rawCritical.let {
            when (it) {
                null -> null
                0x00.toByte() -> false
                else -> true
            }
        }
    }

    override fun equals(other: Any?): Boolean =
        other is X509CertificateExtension &&
                oid == other.oid &&
                rawCritical == other.rawCritical &&
                value.contentEquals(other.value)

    override fun hashCode(): Int {
        var result = oid.hashCode()
        result = 31 * result + (rawCritical?.hashCode() ?: 0)
        result = 31 * result + value.contentHashCode()
        return result
    }
}
