// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.Identifiable
import at.asitplus.awesn1.ObjectIdentifier
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class RelativeDistinguishedName(val attrsAndValues: Set<AttributeTypeAndValue>) {
    constructor(singleItem: AttributeTypeAndValue) : this(setOf(singleItem))
}

@Serializable
data class AttributeTypeAndValue(
    override val oid: ObjectIdentifier,
    val value: Asn1Element,
) : Identifiable {
    constructor(oid: ObjectIdentifier, str: Asn1String) : this(
        oid,
        Asn1Primitive(str.tag, str.value.encodeToByteArray()),
    )

    override fun toString() = value.toString()

    companion object {
        val COMMON_NAME_OID = ObjectIdentifier("2.5.4.3")
        val COUNTRY_OID = ObjectIdentifier("2.5.4.6")
        val ORGANIZATION_OID = ObjectIdentifier("2.5.4.10")
        val ORGANIZATIONAL_UNIT_OID = ObjectIdentifier("2.5.4.11")

        fun commonName(value: Asn1Element) = AttributeTypeAndValue(COMMON_NAME_OID, value)
        fun commonName(value: Asn1String) = AttributeTypeAndValue(COMMON_NAME_OID, value)
        fun country(value: Asn1Element) = AttributeTypeAndValue(COUNTRY_OID, value)
        fun country(value: Asn1String) = AttributeTypeAndValue(COUNTRY_OID, value)
        fun organization(value: Asn1Element) = AttributeTypeAndValue(ORGANIZATION_OID, value)
        fun organization(value: Asn1String) = AttributeTypeAndValue(ORGANIZATION_OID, value)
        fun organizationalUnit(value: Asn1Element) = AttributeTypeAndValue(ORGANIZATIONAL_UNIT_OID, value)
        fun organizationalUnit(value: Asn1String) = AttributeTypeAndValue(ORGANIZATIONAL_UNIT_OID, value)
    }
}
