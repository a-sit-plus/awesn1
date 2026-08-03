// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Identifiable
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.unaryPlus
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Der
import at.asitplus.awesn1.serialization.LenientSet
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlin.experimental.ExperimentalObjCRefinement
import kotlin.native.HiddenFromObjC

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
@ConsistentCopyVisibility
@Serializable
data class Pkcs10CsrAttribute private constructor(
    override val oid: ObjectIdentifier,
    val rawValue: LenientSet<Asn1Element>,
) : Identifiable {
    constructor(oid: ObjectIdentifier, value: Set<Asn1Element>) : this(oid, LenientSet(value)) {
        require(value.isNotEmpty()) { "At least one attribute value is required" }
    }

    constructor(id: ObjectIdentifier, singleElement: Asn1Element) : this(id, setOf(singleElement))

    /**
     * Returns this attribute's values iff decoded input was non-empty and did not contain duplicates.
     *
     * @throws Asn1Exception if the encoded values were malformed
     */
    @OptIn(ExperimentalObjCRefinement::class)
    @Suppress("WRONG_ANNOTATION_TARGET_WITH_USE_SITE_TARGET")
    @get:Throws(Asn1Exception::class)
    @HiddenFromObjC
    @get:HiddenFromObjC
    val value: Set<Asn1Element> get() = rawValue.toValidatedSet().also {
        if (it.isEmpty()) throw Asn1Exception("At least one attribute value is required")
    }

    companion object {
        val EXTENSION_REQUEST_OID = ObjectIdentifier("1.2.840.113549.1.9.14")

        /**
         * Throws on illegal input
         */
        @Throws(IllegalArgumentException::class, SerializationException::class, Asn1Exception::class)
        fun ExtensionRequest(extensions: List<X509CertificateExtension>, der: Der = DER): Pkcs10CsrAttribute {
            require(extensions.isNotEmpty()) { "At least one extension is required" }
            return Pkcs10CsrAttribute(
                EXTENSION_REQUEST_OID,
                singleElement = with(der) { Asn1.Sequence { extensions.forEach { +it } } }
            )
        }
    }
}
