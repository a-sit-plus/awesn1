// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Encodable
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.Identifiable
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.decodeRethrowing
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.readOid
import at.asitplus.awesn1.serialization.Asn1Serializable
import kotlinx.serialization.Serializable

@Serializable(with = Attribute.Companion::class)
open class Attribute(
    override val oid: ObjectIdentifier,
    val value: List<Asn1Element>
) : Asn1Encodable<Asn1Sequence>, Identifiable {
    constructor(id: ObjectIdentifier, value: Asn1Element) : this(id, listOf(value))

    override fun encodeToTlv() = Asn1.Sequence {
        +oid
        +Asn1.Set { value.forEach { +it } }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Attribute) return false
        return oid == other.oid && value == other.value
    }

    override fun hashCode(): Int = 31 * oid.hashCode() + value.hashCode()

    companion object : Asn1Serializable<Asn1Sequence, Attribute> {
        override val leadingTags = setOf(Asn1Element.Tag.SEQUENCE)

        private val EXTENSION_REQUEST_OID = ObjectIdentifier("1.2.840.113549.1.9.14")

        fun extensionRequest(extensions: List<X509CertificateExtension>): Attribute {
            require(extensions.isNotEmpty()) { "At least one extension is required" }
            return Attribute(
                EXTENSION_REQUEST_OID,
                Asn1.Sequence { extensions.forEach { +it } }
            )
        }

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): Attribute = src.decodeRethrowing {
            val id = next().asPrimitive().readOid()
            val value = next().asSet().children
            Attribute(id, value)
        }
    }
}
