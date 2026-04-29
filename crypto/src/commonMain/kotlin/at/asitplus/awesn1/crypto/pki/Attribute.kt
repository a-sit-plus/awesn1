// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Identifiable
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.encoding.Asn1
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
data class Attribute(
    override val oid: ObjectIdentifier,
    val value: Set<Asn1Element>,
) : Identifiable {
    constructor(id: ObjectIdentifier, value: Asn1Element) : this(id, setOf(value))

    companion object {
        private val EXTENSION_REQUEST_OID = ObjectIdentifier("1.2.840.113549.1.9.14")

        fun extensionRequest(extensions: List<X509CertificateExtension>): Attribute {
            require(extensions.isNotEmpty()) { "At least one extension is required" }
            return Attribute(
                EXTENSION_REQUEST_OID,
                Asn1.Sequence {
                    extensions.forEach { ext ->
                        +Asn1.Sequence {
                            +ext.oid
                            ext.critical?.let { +Asn1.Bool(it) }
                            +Asn1.OctetString(ext.value)
                        }
                    }
                },
            )
        }
    }
}
