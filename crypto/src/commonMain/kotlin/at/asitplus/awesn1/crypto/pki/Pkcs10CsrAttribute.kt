// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Identifiable
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.encodeToTlv
import kotlinx.serialization.Serializable

/**
 *
 * As per [RFC2986](https://www.rfc-editor.org/rfc/rfc2986.html#section-4.1):
 * ```
 * Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
 *   type   ATTRIBUTE.&id({IOSet}),
 *   values SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{@type})
 * }
 * ```
 */
@Serializable
data class Pkcs10CsrAttribute(
    override val oid: ObjectIdentifier,
    val value: Set<Asn1Element>,
) : Identifiable {
    constructor(id: ObjectIdentifier, value: Asn1Element) : this(id, setOf(value))

    companion object {
        val EXTENSION_REQUEST_OID = ObjectIdentifier("1.2.840.113549.1.9.14")

        fun ExtensionRequest(extensions: List<X509CertificateExtension>): Pkcs10CsrAttribute {
            require(extensions.isNotEmpty()) { "At least one extension is required" }
            return Pkcs10CsrAttribute(
                EXTENSION_REQUEST_OID,
                Asn1.Sequence { extensions.forEach { +DER.encodeToTlv(it) } },
            )
        }
    }
}
