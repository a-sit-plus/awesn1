// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.Asn1Decodable
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Encodable
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.Asn1Structure
import at.asitplus.awesn1.Asn1StructuralException
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.runWrappingAs
import at.asitplus.awesn1.serialization.Asn1Serializer
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.decodeFromTlv
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Deprecated("Use X509GeneralNames instead", ReplaceWith("X509GeneralNames"))
typealias GeneralNames = X509GeneralNames

/**
 * The RFC 5280 `GeneralName` CHOICE.
 *
 * Decoding validates only the outer CHOICE tag and preserves its complete ASN.1 representation. Typed payload
 * accessors decode lazily and may therefore throw for malformed payloads. This permits lossless round-tripping of
 * certificates whose general names are structurally recognizable but whose payloads are broken.
 */
@Serializable(with = X509GeneralName.Companion::class)
sealed class X509GeneralName private constructor(
    val asn1Representation: Asn1Element,
) : Asn1Encodable<Asn1Element> {


    final override fun encodeToTlv(): Asn1Element = asn1Representation

    final override fun equals(other: Any?): Boolean =
        this === other || (other is X509GeneralName && asn1Representation == other.asn1Representation)

    final override fun hashCode(): Int = 31 * asn1Representation.hashCode()

    final override fun toString(): String = "X509GeneralName($asn1Representation)"

    class OtherName internal constructor(private val raw: Asn1Structure) : X509GeneralName(raw) {

        private val parsed: Pair<ObjectIdentifier, Asn1Element> by lazy {
            if (raw.children.size != 2)
                throw Asn1StructuralException("Invalid otherName: expected two children, got ${raw.children.size}")
            val typeId = ObjectIdentifier.decodeFromAsn1ContentBytes(raw.children[0].asPrimitive().content)
            val valueWrapper = raw.children[1]
            if (valueWrapper.tag != Tags.otherNameValue)
                throw Asn1StructuralException("Invalid otherName: expected an explicitly tagged [0] value")
            val values = valueWrapper.asStructure().children
            if (values.size != 1)
                throw Asn1StructuralException("Invalid otherName value: expected one child, got ${values.size}")
            typeId to values.single()
        }

        val typeId: ObjectIdentifier get() = parsed.first
        val value: Asn1Element get() = parsed.second

        constructor(typeId: ObjectIdentifier, value: Asn1Element) : this(
            (Asn1.Sequence {
                +typeId.encodeToTlv()
                +Asn1.ExplicitlyTagged(0u) { +value }
            } withImplicitTag Tags.otherName).asStructure()
        )
    }

    class Rfc822Name internal constructor(private val raw: Asn1Primitive) : X509GeneralName(raw) {
        val value: String by lazy { decodeIa5(raw, Tags.rfc822Name) }
        constructor(value: String) : this(encodeIa5(value, Tags.rfc822Name))
    }

    class DnsName internal constructor(private val raw: Asn1Primitive) : X509GeneralName(raw) {
        val value: String by lazy { decodeIa5(raw, Tags.dnsName) }
        constructor(value: String) : this(encodeIa5(value, Tags.dnsName))
    }

    class X400Address internal constructor(private val raw: Asn1Structure) : X509GeneralName(raw) {
        val value: Asn1Sequence by lazy { raw.asImplicitSequence() }
        constructor(value: Asn1Sequence) : this((value withImplicitTag Tags.x400Address).asStructure())
    }

    class DirectoryName internal constructor(private val raw: Asn1Structure) : X509GeneralName(raw) {
        val value: X500Name by lazy {
            if (raw.children.size != 1)
                throw Asn1StructuralException("Invalid directoryName: expected one child, got ${raw.children.size}")
            DER.decodeFromTlv(raw.children.single())
        }

        constructor(value: X500Name) : this(
            Asn1.ExplicitlyTagged(4u) { +DER.encodeToTlv(X500Name.serializer(), value) }
        )
    }

    class EdiPartyName internal constructor(private val raw: Asn1Structure) : X509GeneralName(raw) {
        val value: Asn1Sequence by lazy { raw.asImplicitSequence() }
        constructor(value: Asn1Sequence) : this((value withImplicitTag Tags.ediPartyName).asStructure())
    }

    class UniformResourceIdentifier internal constructor(private val raw: Asn1Primitive) : X509GeneralName(raw) {
        val value: String by lazy { decodeIa5(raw, Tags.uniformResourceIdentifier) }
        constructor(value: String) : this(encodeIa5(value, Tags.uniformResourceIdentifier))
    }

    class IpAddress internal constructor(private val raw: Asn1Primitive) : X509GeneralName(raw) {
        val value: ByteArray get() = raw.content
        constructor(value: ByteArray) : this(Asn1Primitive(Tags.ipAddress, value))
    }

    class RegisteredId internal constructor(private val raw: Asn1Primitive) : X509GeneralName(raw) {
        val value: ObjectIdentifier by lazy { ObjectIdentifier.decodeFromAsn1ContentBytes(raw.content) }
        constructor(value: ObjectIdentifier) : this(Asn1Primitive(Tags.registeredID, value.bytes))
    }

    /** Context-specific tags for RFC 5280 `GeneralName` alternatives. */
    object Tags {
        val otherName = Asn1.ExplicitTag(0u)
        val rfc822Name = Asn1.ImplicitTag(1u)
        val dnsName = Asn1.ImplicitTag(2u)
        val x400Address = Asn1.ExplicitTag(3u)
        val directoryName = Asn1.ExplicitTag(4u)
        val ediPartyName = Asn1.ExplicitTag(5u)
        val uniformResourceIdentifier = Asn1.ImplicitTag(6u)
        val ipAddress = Asn1.ImplicitTag(7u)
        val registeredID = Asn1.ImplicitTag(8u)
        val otherNameValue = Asn1.ExplicitTag(0u)

        internal val all = setOf(
            otherName, rfc822Name, dnsName, x400Address, directoryName,
            ediPartyName, uniformResourceIdentifier, ipAddress, registeredID,
        )
    }

    //Tagging is a real mess, so we need thi
    companion object : Asn1Serializer<Asn1Element, X509GeneralName>(
        leadingTags = Tags.all,
        decodable = object : Asn1Decodable<Asn1Element, X509GeneralName> {
            override fun doDecode(src: Asn1Element): X509GeneralName = when (src.tag) {
                Tags.otherName -> OtherName(src.asStructure())
                Tags.rfc822Name -> Rfc822Name(src.asPrimitive())
                Tags.dnsName -> DnsName(src.asPrimitive())
                Tags.x400Address -> X400Address(src.asStructure())
                Tags.directoryName -> DirectoryName(src.asStructure())
                Tags.ediPartyName -> EdiPartyName(src.asStructure())
                Tags.uniformResourceIdentifier -> UniformResourceIdentifier(src.asPrimitive())
                Tags.ipAddress -> IpAddress(src.asPrimitive())
                Tags.registeredID -> RegisteredId(src.asPrimitive())
                else -> throw Asn1StructuralException("Unknown GeneralName tag: ${src.tag}")
            }
        },
    )
}

private fun decodeIa5(raw: Asn1Primitive, tag: Asn1Element.Tag): String =
    at.asitplus.awesn1.Asn1Ia5StringSerializer.decodeFromTlv(raw, tag).value

private fun encodeIa5(value: String, tag: Asn1Element.Tag): Asn1Primitive =
    (Asn1String.IA5(value).encodeToTlv() withImplicitTag tag).asPrimitive()

private fun Asn1Structure.asImplicitSequence(): Asn1Sequence = Asn1.Sequence { children.forEach { +it } }

/** `GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName`. */
@JvmInline
@Serializable
value class X509GeneralNames @Throws(Throwable::class) constructor(
    val entries: List<X509GeneralName>
) {
    val dnsNames: List<String> get() = entries.filterIsInstance<X509GeneralName.DnsName>().map { it.value }
    val rfc822Names: List<String> get() = entries.filterIsInstance<X509GeneralName.Rfc822Name>().map { it.value }
    val uris: List<String> get() = entries.filterIsInstance<X509GeneralName.UniformResourceIdentifier>().map { it.value }
    val ipAddresses: List<ByteArray> get() = entries.filterIsInstance<X509GeneralName.IpAddress>().map { it.value }
    val directoryNames: List<X500Name> get() = entries.filterIsInstance<X509GeneralName.DirectoryName>().map { it.value }
    val otherNames: List<X509GeneralName.OtherName> get() = entries.filterIsInstance<X509GeneralName.OtherName>()

    companion object {
        @Throws(Asn1Exception::class)
        fun X509Certificate.findSubjectAltNames() = tbsCertificate.findSubjectAltNames()
        @Throws(Asn1Exception::class)
        fun X509TbsCertificate.findSubjectAltNames() = extensions?.findSubjectAltNames()

        @Throws(Asn1Exception::class)
        fun List<X509CertificateExtension>.findSubjectAltNames() =
            runWrappingAs(a = ::Asn1Exception) { find(ObjectIdentifier("2.5.29.17"))?.let(::X509GeneralNames) }

        @Throws(Asn1Exception::class)
        fun X509Certificate.findIssuerAltNames() = tbsCertificate.findIssuerAltNames()
        @Throws(Asn1Exception::class)
        fun X509TbsCertificate.findIssuerAltNames() = extensions?.findIssuerAltNames()

        @Throws(Asn1Exception::class)
        fun List<X509CertificateExtension>.findIssuerAltNames() =
            runWrappingAs(a = ::Asn1Exception) { find(ObjectIdentifier("2.5.29.18"))?.let(::X509GeneralNames) }

        private fun List<X509CertificateExtension>.find(oid: ObjectIdentifier): List<X509GeneralName>? {
            val matches = filter { it.oid == oid }
            if (matches.size > 1) throw Asn1StructuralException("More than one extension with oid $oid found")
            return matches.singleOrNull()?.let { extension ->
                Asn1Element.parse(extension.value).asSequence().children.map { DER.decodeFromTlv(it) }
            }
        }
    }
}
