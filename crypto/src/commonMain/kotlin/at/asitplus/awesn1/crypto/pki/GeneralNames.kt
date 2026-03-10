// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1EncapsulatingOctetString
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.Asn1StructuralException
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.runRethrowing
import at.asitplus.awesn1.encoding.Asn1

open class GeneralNames @Throws(Throwable::class) constructor(
    val entries: List<Asn1Element>
) {

    val dnsNames: List<String>? = parseStringSANs(GeneralNameImplicitTags.dNSName)
    val rfc822Names: List<String>? = parseStringSANs(GeneralNameImplicitTags.rfc822Name)
    val uris: List<String>? = parseStringSANs(GeneralNameImplicitTags.uniformResourceIdentifier)

    val ipAddresses: List<ByteArray> = entries.filter { it.tag == GeneralNameImplicitTags.iPAddress }.apply {
        forEach {
            if (it !is Asn1Primitive)
                throw Asn1StructuralException("Invalid iPAddress Alternative Name found: ${it.toDerHexString()}")
            else if (it.content.size != 4 && it.content.size != 16) throw Asn1StructuralException("Invalid iPAddress Alternative Name found: ${it.toDerHexString()}")
        }
    }.map { (it as Asn1Primitive).content }

    val directoryNames: List<List<RelativeDistinguishedName>> =
        entries.filter { it.tag == GeneralNameImplicitTags.directoryName }.apply {
            forEach {
                if (it !is Asn1Sequence) throw Asn1StructuralException("Invalid directoryName Alternative Name found: ${it.toDerHexString()}")
            }
        }.map { (it as Asn1Sequence).children.map { RelativeDistinguishedName.decodeFromTlv(it.asSet()) } }

    val otherNames: List<Asn1Sequence> =
        entries.filter { it.tag == GeneralNameImplicitTags.otherName }.apply {
            forEach {
                if (it !is Asn1Sequence) throw Asn1StructuralException("Invalid otherName Alternative Name found: ${it.toDerHexString()}")
            }
        }.map {
            (it as Asn1Sequence).also {
                if (it.children.size != 2) throw Asn1StructuralException("Invalid otherName Alternative Name found (!=2 children): ${it.toDerHexString()}")
                if (it.children.last().tag != GeneralNameImplicitTags.otherName) throw Asn1StructuralException("Invalid otherName Alternative Name found (implicit tag != 0): ${it.toDerHexString()}")
                ObjectIdentifier.decodeFromAsn1ContentBytes((it.children.first() as Asn1Primitive).content)
            }
        }

    private fun parseStringSANs(implicitTag: Asn1Element.Tag) =
        entries.filter { it.tag == implicitTag }.apply {
            forEach { if (it !is Asn1Primitive) throw Asn1StructuralException("Invalid string GeneralName found: ${it.toDerHexString()}") }
        }.map { (it as Asn1Primitive).content.decodeToString() }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is GeneralNames) return false
        return entries == other.entries
    }

    override fun hashCode(): Int = entries.hashCode()

    companion object {
        @Throws(Asn1Exception::class)
        fun List<X509CertificateExtension>.findSubjectAltNames() = runRethrowing {
            find(ObjectIdentifier("2.5.29.17"))?.let { GeneralNames(it) }
        }

        @Throws(Asn1Exception::class)
        fun List<X509CertificateExtension>.findIssuerAltNames() = runRethrowing {
            find(ObjectIdentifier("2.5.29.18"))?.let { GeneralNames(it) }
        }

        private fun List<X509CertificateExtension>.find(oid: ObjectIdentifier): List<Asn1Element>? {
            val matches = filter { it.oid == oid }
            if (matches.size > 1) throw Asn1StructuralException("More than one extension with oid $oid found")
            return if (matches.isEmpty()) null
            else ((matches.first().value as Asn1EncapsulatingOctetString).children.firstOrNull() as Asn1Sequence?)?.children
        }
    }
}

object GeneralNameImplicitTags {
    val otherName = Asn1.ImplicitTag(0uL)
    val rfc822Name = Asn1.ImplicitTag(1uL)
    val dNSName = Asn1.ImplicitTag(2uL)
    val x400Address = Asn1.ImplicitTag(3uL)
    val directoryName = Asn1.ImplicitTag(4uL)
    val ediPartyName = Asn1.ImplicitTag(5uL)
    val uniformResourceIdentifier = Asn1.ImplicitTag(6uL)
    val iPAddress = Asn1.ImplicitTag(7uL)
    val registeredID = Asn1.ImplicitTag(8uL)
}
