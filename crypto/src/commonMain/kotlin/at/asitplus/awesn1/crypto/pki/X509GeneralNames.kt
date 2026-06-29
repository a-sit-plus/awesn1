// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.Asn1StructuralException
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.TagClass
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.runRethrowing
import at.asitplus.awesn1.runWrappingAs
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.decodeFromTlv
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Deprecated("Use X509GeneralNames instead", ReplaceWith("X509GeneralNames"))
typealias GeneralNames = X509GeneralNames

/**
 *
 * As per [RFC5280](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.6):
 * ```
 * SubjectAltName ::= GeneralNames
 *
 * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
 *
 * GeneralName ::= CHOICE {
 *   otherName                       [0]     OtherName,
 *   rfc822Name                      [1]     IA5String,
 *   dNSName                         [2]     IA5String,
 *   x400Address                     [3]     ORAddress,
 *   directoryName                   [4]     Name,
 *   ediPartyName                    [5]     EDIPartyName,
 *   uniformResourceIdentifier       [6]     IA5String,
 *   iPAddress                       [7]     OCTET STRING,
 *   registeredID                    [8]     OBJECT IDENTIFIER
 * }
 * ```
 */
@JvmInline
@Serializable
value class X509GeneralNames @Throws(Throwable::class) constructor(
    val entries: List<Asn1Element>
) {

    private fun parseStringSANs(implicitTag: Asn1Element.Tag) =
        entries.filter { it.tag == implicitTag }.map { it.asPrimitive().content.decodeToString() }
    val dnsNames: List<String> get() = parseStringSANs(GeneralNameTags.dnsName)
    val rfc822Names: List<String> get() = parseStringSANs(GeneralNameTags.rfc822Name)
    val uris: List<String> get() = parseStringSANs(GeneralNameTags.uniformResourceIdentifier)

    val ipAddresses: List<ByteArray> get() =
        entries.filter { it.tag == GeneralNameTags.ipAddress }
            .map { it.asPrimitive().content.also { c ->
                if (c.size != 4 && c.size != 16) throw Asn1StructuralException("Invalid ipAddress Alternative Name found: ${c.toHexString()}")
            }}

    // runRethrowing: this getter parses attacker-controlled bytes; an empty or multi-child [4] wrapper would
    // otherwise leak NoSuchElementException/IllegalArgumentException instead of a catchable Asn1Exception.
    val directoryNames: List<List<X500RelativeDistinguishedName>> get() = runRethrowing {
        entries.filter { it.tag == GeneralNameTags.directoryName }
            .map { e ->
                val wrapper = e.asStructure().children
                if (wrapper.size != 1)
                    throw Asn1StructuralException("Invalid directoryName: expected a single child, got ${wrapper.size}")
                wrapper.single().asSequence().children
                    .map { DER.decodeFromTlv<X500RelativeDistinguishedName>(it) }
            }
    }

    val otherNames: List<Asn1Sequence> get() =
        entries.filter { it.tag == GeneralNameTags.otherName }.map { e ->
            e.asStructure().let {
                if (it.children.size != 2) throw Asn1StructuralException("Invalid otherName Alternative Name found (!=2 children): ${it.toDerHexString()}")
                if (it.children.last().tag != GeneralNameTags.otherNameValue) throw Asn1StructuralException("Invalid otherName Alternative Name found (explicit value tag != 0): ${it.toDerHexString()}")
                ObjectIdentifier.decodeFromAsn1ContentBytes(it.children.first().asPrimitive().content)
                Asn1.Sequence { it.children.forEach { child -> +child } }
            }
        }

    companion object {
        @Throws(Asn1Exception::class)
        fun X509Certificate.findSubjectAltNames() = tbsCertificate.findSubjectAltNames()
        @Throws(Asn1Exception::class)
        fun X509TbsCertificate.findSubjectAltNames() = extensions?.findSubjectAltNames()

        @Throws(Asn1Exception::class)
        fun List<X509CertificateExtension>.findSubjectAltNames() =
            runWrappingAs(a=::Asn1Exception) {
                find(ObjectIdentifier("2.5.29.17"))?.let { X509GeneralNames(it) }
            }

        @Throws(Asn1Exception::class)
        fun X509Certificate.findIssuerAltNames() = tbsCertificate.findIssuerAltNames()
        @Throws(Asn1Exception::class)
        fun X509TbsCertificate.findIssuerAltNames() = extensions?.findIssuerAltNames()

        @Throws(Asn1Exception::class)
        fun List<X509CertificateExtension>.findIssuerAltNames() =
            runWrappingAs(a=::Asn1Exception) {
                find(ObjectIdentifier("2.5.29.18"))?.let { X509GeneralNames(it) }
            }

        private fun List<X509CertificateExtension>.find(oid: ObjectIdentifier): List<Asn1Element>? {
            val matches = filter { it.oid == oid }
            if (matches.size > 1) throw Asn1StructuralException("More than one extension with oid $oid found")
            return if (matches.isEmpty()) null
            else Asn1Element.parse(matches.first().value).asSequence().children
        }
    }
}

/**
 *
 * Context-specific tags for RFC 5280 `GeneralName` alternatives.
 */
object GeneralNameTags {
    val otherName = constructedContextTag(0uL)
    val rfc822Name = Asn1.ImplicitTag(1uL)
    val dnsName = Asn1.ImplicitTag(2uL)
    val x400Address = constructedContextTag(3uL)

    /*
     * `directoryName [4] Name` is encoded as a constructed wrapper because
     * `Name` is itself a CHOICE and has no tag that implicit tagging could replace.
     */
    val directoryName = constructedContextTag(4uL)

    val ediPartyName = constructedContextTag(5uL)
    val uniformResourceIdentifier = Asn1.ImplicitTag(6uL)
    val ipAddress = Asn1.ImplicitTag(7uL)
    val registeredID = Asn1.ImplicitTag(8uL)

    /** `OtherName.value [0] EXPLICIT ANY DEFINED BY type-id`. */
    val otherNameValue = Asn1.ExplicitTag(0uL)

    //same as explicit tag, but like this the source code reads close to the semantics:
    //an implicitly tagged CONSTRUCTED element
    private fun constructedContextTag(tagNumber: ULong) =
        Asn1Element.Tag(tagNumber, constructed = true, tagClass = TagClass.CONTEXT_SPECIFIC)
}
