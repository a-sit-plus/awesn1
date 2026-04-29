// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.Asn1EncapsulatingOctetString
import at.asitplus.awesn1.Asn1PrimitiveOctetString
import at.asitplus.awesn1.Identifiable
import at.asitplus.awesn1.ObjectIdentifier
import kotlinx.serialization.Serializable

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
data class X509CertificateExtension(
    override val oid: ObjectIdentifier,
    val critical: Boolean? = null,
    val value: ByteArray,
) : Identifiable {

    constructor(
        oid: ObjectIdentifier,
        critical: Boolean = false,
        value: Asn1EncapsulatingOctetString,
    ) : this(oid, critical.takeIf { it }, value.content)

    constructor(
        oid: ObjectIdentifier,
        critical: Boolean = false,
        value: Asn1PrimitiveOctetString,
    ) : this(oid, critical.takeIf { it }, value.content)

    override fun equals(other: Any?): Boolean =
        other is X509CertificateExtension &&
            oid == other.oid &&
            critical == other.critical &&
            value.contentEquals(other.value)

    override fun hashCode(): Int {
        var result = oid.hashCode()
        result = 31 * result + (critical?.hashCode() ?: 0)
        result = 31 * result + value.contentHashCode()
        return result
    }
}
