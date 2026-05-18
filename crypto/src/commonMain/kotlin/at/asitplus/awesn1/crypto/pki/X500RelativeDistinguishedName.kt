// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.Identifiable
import at.asitplus.awesn1.ObjectIdentifier
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Deprecated("Use X500RelativeDistinguishedName instead", ReplaceWith("X500RelativeDistinguishedName"))
typealias RelativeDistinguishedName = X500RelativeDistinguishedName

/**
 *
 * As per [RFC5280](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.4):
 * ```
 *    RelativeDistinguishedName ::=
 *      SET SIZE (1..MAX) OF AttributeTypeAndValue
 * ```
 */

@Serializable
@JvmInline
value class X500RelativeDistinguishedName(val attrsAndValues: Set<X500AttributeTypeAndValue>) {
    constructor(singleItem: X500AttributeTypeAndValue) : this(setOf(singleItem))
}

/**
 *
 * As per [RFC5280](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.4):
 * ```
 *    AttributeTypeAndValue ::= SEQUENCE {
 *      type     AttributeType,
 *      value    AttributeValue }
 *
 *    AttributeType ::= OBJECT IDENTIFIER
 *
 *    AttributeValue ::= ANY -- DEFINED BY AttributeType
 *
 *    DirectoryString ::= CHOICE {
 *          teletexString           TeletexString (SIZE (1..MAX)),
 *          printableString         PrintableString (SIZE (1..MAX)),
 *          universalString         UniversalString (SIZE (1..MAX)),
 *          utf8String              UTF8String (SIZE (1..MAX)),
 *          bmpString               BMPString (SIZE (1..MAX)) }
 *  ```
 *
 *  The Name describes a hierarchical name composed of attributes, such
 *  as country name, and corresponding values, such as US.  The type of
 *  the component `AttributeValue` is determined by the `AttributeType`; in
 *  general it will be a `DirectoryString`.
 *
 *  This class does not perform semantic validations.
 */
@ConsistentCopyVisibility
@Serializable
data class X500AttributeTypeAndValue(
    override val oid: ObjectIdentifier,
    val value: Asn1Element,
) : Identifiable {
    constructor(oid: ObjectIdentifier, str: Asn1String) : this(
        oid,
        str.encodeToTlv(),
    )

    override fun toString() = value.toString()

    @Suppress("FunctionName")
    companion object {
        //because we don't want to depend on KnownOIDs
        val COMMON_NAME_OID = ObjectIdentifier("2.5.4.3")
        val COUNTRY_OID = ObjectIdentifier("2.5.4.6")
        val ORGANIZATION_OID = ObjectIdentifier("2.5.4.10")
        val ORGANIZATIONAL_UNIT_OID = ObjectIdentifier("2.5.4.11")

        fun CommonName(value: Asn1String) = X500AttributeTypeAndValue(COMMON_NAME_OID, value)
        fun Country(value: Asn1String) = X500AttributeTypeAndValue(COUNTRY_OID, value)
        fun Organization(value: Asn1String) = X500AttributeTypeAndValue(ORGANIZATION_OID, value)
        fun OrganizationalUnit(value: Asn1String) = X500AttributeTypeAndValue(ORGANIZATIONAL_UNIT_OID, value)
    }
}
