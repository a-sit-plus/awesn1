// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1EncapsulatingOctetString
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.Asn1StructuralException
import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.runWrappingAs
import kotlin.jvm.JvmInline

@JvmInline
value class GeneralNames @Throws(Throwable::class) constructor(
    val entries: List<Asn1Element>
) {

    private fun parseStringSANs(implicitTag: Asn1Element.Tag) =
        entries.filter { it.tag == implicitTag }.map { it.asPrimitive().content.decodeToString() }
    val dnsNames: List<String> get() = parseStringSANs(GeneralNameImplicitTags.dnsName)
    val rfc822Names: List<String> get() = parseStringSANs(GeneralNameImplicitTags.rfc822Name)
    val uris: List<String> get() = parseStringSANs(GeneralNameImplicitTags.uniformResourceIdentifier)

    val ipAddresses: List<ByteArray> get() =
        entries.filter { it.tag == GeneralNameImplicitTags.ipAddress }
            .map { it.asPrimitive().content.also { c ->
                if (c.size != 4 && c.size != 16) throw Asn1StructuralException("Invalid ipAddress Alternative Name found: ${c.toHexString()}")
            }}

    val directoryNames: List<List<RelativeDistinguishedName>> get() =
        entries.filter { it.tag == GeneralNameImplicitTags.directoryName }
            .map { e -> e.asSequence().children.map { RelativeDistinguishedName.decodeFromTlv(it.asSet()) } }

    val otherNames: List<Asn1Sequence> get() =
        entries.filter { it.tag == GeneralNameImplicitTags.otherName }.map { e ->
            e.asSequence().also {
                if (it.children.size != 2) throw Asn1StructuralException("Invalid otherName Alternative Name found (!=2 children): ${it.toDerHexString()}")
                if (it.children.last().tag != GeneralNameImplicitTags.otherName) throw Asn1StructuralException("Invalid otherName Alternative Name found (implicit tag != 0): ${it.toDerHexString()}")
                ObjectIdentifier.decodeFromAsn1ContentBytes(it.children.first().asPrimitive().content)
            }
        }

    companion object {
        @Throws(Asn1Exception::class)
        fun X509Certificate.findSubjectAltNames() = tbsCertificate.findSubjectAltNames()
        @Throws(Asn1Exception::class)
        fun TbsCertificate.findSubjectAltNames() = extensions?.findSubjectAltNames()

        @Throws(Asn1Exception::class)
        fun List<X509CertificateExtension>.findSubjectAltNames() =
            runWrappingAs(a=::Asn1Exception) {
                find(ObjectIdentifier("2.5.29.17"))?.let { GeneralNames(it) }
            }

        @Throws(Asn1Exception::class)
        fun X509Certificate.findIssuerAltNames() = tbsCertificate.findIssuerAltNames()
        @Throws(Asn1Exception::class)
        fun TbsCertificate.findIssuerAltNames() = extensions?.findIssuerAltNames()

        @Throws(Asn1Exception::class)
        fun List<X509CertificateExtension>.findIssuerAltNames() =
            runWrappingAs(a=::Asn1Exception) {
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
    val dnsName = Asn1.ImplicitTag(2uL)
    val x400Address = Asn1.ImplicitTag(3uL)
    val directoryName = Asn1.ImplicitTag(4uL)
    val ediPartyName = Asn1.ImplicitTag(5uL)
    val uniformResourceIdentifier = Asn1.ImplicitTag(6uL)
    val ipAddress = Asn1.ImplicitTag(7uL)
    val registeredID = Asn1.ImplicitTag(8uL)
}
