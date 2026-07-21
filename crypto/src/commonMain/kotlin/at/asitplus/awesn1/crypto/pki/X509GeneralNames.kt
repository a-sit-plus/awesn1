// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.serialization.*
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

/**
 * The RFC 5280 `GeneralName` CHOICE.
 *
 * Closed alternatives are decoded as strict typed values. The open `otherName` arm delegates its payload to an
 * OID-selected [X509GeneralName.Other.SemanticValue] implementation.
 *
 * In general, if the tag matches and the ASN1 element type is correct, it will leniently decode where this makes sense,
 * such as [X509GeneralName.Rfc822], or other string-based ones.
 */
@Serializable
sealed interface X509GeneralName {


    /** The `[0]` GeneralName arm containing an open [SemanticValue] value.
     * Trying to parse a structurally malformed input will fail.
     **/
    @Serializable
    @JvmInline
    @Asn1Tag(tagNumber = 0u, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    value class Other(val value: SemanticValue) : X509GeneralName {
        /** Open, OID-discriminated `otherName` value. */
        @Serializable(with = SemanticValue.Serializer::class)
        interface SemanticValue : Identifiable {
            /** Structural fallback for an `otherName` OID without a registered semantic subtype. */
            @Serializable
            data class Generic(
                override val oid: ObjectIdentifier,
                @Asn1Tag(tagNumber = 0u, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
                private val taggedValue: ExplicitlyTagged<Asn1Element>,
            ) : SemanticValue {
                val typeId: ObjectIdentifier get() = oid
                val value: Asn1Element get() = taggedValue.value

                constructor(typeId: ObjectIdentifier, value: Asn1Element) : this(typeId, ExplicitlyTagged(value))
            }

            object Serializer : Asn1OpenPolymorphicWithDefaultSerializer<SemanticValue>(
                baseClass = SemanticValue::class,
                defaultSerializer = asn1OpenPolymorphicByOidSerializer("X509OtherName") {
                    catchAll<Generic>()
                },
            )
        }
    }

    /**Will be parsed leniently*/
    @Serializable
    @JvmInline
    @Asn1Tag(tagNumber = 1u, constructed = Asn1Tag.ConstructedBit.PRIMITIVE)
    value class Rfc822 private constructor(val rawValue: Asn1String.IA5) : X509GeneralName {

        val value: String get() = if (!rawValue.isValid) throw Asn1Exception("Malformed RFC822Name IA5String payload") else rawValue.value

        constructor(value: String) : this(Asn1String.IA5(value))
    }

    /**Will be parsed leniently*/
    @Serializable
    @JvmInline
    @Asn1Tag(tagNumber = 2u, constructed = Asn1Tag.ConstructedBit.PRIMITIVE)
    value class Dns private constructor(val rawValue: Asn1String.IA5) : X509GeneralName {

        val value: String get() = if (!rawValue.isValid) throw Asn1Exception("Malformed dNSName IA5String payload") else rawValue.value

        constructor(value: String) : this(Asn1String.IA5(value))
    }


    /**
     *  Trying to parse a structurally malformed input will fail.
     **/
    @Serializable
    @JvmInline
    @Asn1Tag(tagNumber = 3u, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    value class X400Address private constructor(val elements: List<Asn1Element>) : X509GeneralName {

        /**
         * Convenience constructor
         */
        constructor(value: Asn1Sequence) : this(value.children)
    }

    /** The explicitly tagged `directoryName` GeneralName alternative.
     * Trying to parse a structurally malformed input will fail.
     **/
    @Serializable
    @JvmInline
    @Asn1Tag(tagNumber = 4u, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    value class Directory private constructor(
        val taggedValue: ExplicitlyTagged<X500Name>,
    ) : X509GeneralName {
        val value: X500Name get() = taggedValue.value //Value classes cannot have delegated props

        companion object {
            operator fun invoke(value: X500Name) =
                Directory(ExplicitlyTagged(value))
        }
    }

    /**
     * Trying to parse a structurally malformed input will fail.
     **/
    @Serializable
    @JvmInline
    @Asn1Tag(tagNumber = 5u, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    value class EdiParty private constructor(private val elements: List<Asn1Element>) : X509GeneralName {

        /**
         * convenience constructor
         */
        constructor(value: Asn1Sequence) : this(value.children)
    }

    /**Will be parsed leniently*/
    @Serializable
    @JvmInline
    @Asn1Tag(tagNumber = 6u, constructed = Asn1Tag.ConstructedBit.PRIMITIVE)
    value class UniformResourceIdentifier private constructor(val rawValue: Asn1String.IA5) : X509GeneralName {

        val value: String get() = if (!rawValue.isValid) throw Asn1Exception("Malformed uniformResourceIdentifier IA5String payload") else rawValue.value

        constructor(value: String) : this(Asn1String.IA5(value))
    }

    /**Will parse leniently*/
    @Serializable
    @JvmInline
    @Asn1Tag(tagNumber = 7u, constructed = Asn1Tag.ConstructedBit.PRIMITIVE)
    value class IpAddress private constructor(
        /**
         * This contains a raw octet string in case someone was "creative" and encoded an IP address in some cursed, structural manner
         * or as a string inside an OCTET STRING and someone else wants to salvage it
         */
        val rawValue: Asn1OctetString
    ) : X509GeneralName {

        constructor(ipAddress: ByteArray) : this(Asn1OctetString(ipAddress))

        val value: ByteArray
            get() = if (rawValue.content.size != 4 && rawValue.content.size != 16)
                throw Asn1StructuralException("Invalid IP address value: expected 4 or 16 octets, got ${rawValue.content.size}") else rawValue.content

    }

    /**
     * Trying to parse a structurally malformed input will fail.
     */
    @Serializable
    @JvmInline
    @Asn1Tag(tagNumber = 8u, constructed = Asn1Tag.ConstructedBit.PRIMITIVE)
    value class RegisteredId(val oid: ObjectIdentifier) : X509GeneralName

    /** Context-specific tags for RFC 5280 `GeneralName` alternatives. Handy for manually sifting through an X509GeneralName structure. */
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
    }

}

/** `GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName`. */
@JvmInline
@Serializable
value class X509GeneralNames @Throws(Throwable::class) constructor(
    val entries: List<X509GeneralName>
) {
    val dnsNames: List<String> get() = entries.filterIsInstance<X509GeneralName.Dns>().map { it.value }
    val rfc822Names: List<String> get() = entries.filterIsInstance<X509GeneralName.Rfc822>().map { it.value }
    val uris: List<String>
        get() = entries.filterIsInstance<X509GeneralName.UniformResourceIdentifier>().map { it.value }
    val ipAddresses: List<ByteArray> get() = entries.filterIsInstance<X509GeneralName.IpAddress>().map { it.value }
    val directoryNames: List<X500Name>
        get() = entries.filterIsInstance<X509GeneralName.Directory>().map { it.value }
    val otherNames: List<X509GeneralName.Other.SemanticValue>
        get() = entries.filterIsInstance<X509GeneralName.Other>().map { it.value }

    companion object {
        @Throws(Asn1Exception::class)
        fun X509Certificate.findSubjectAltNames(der: Der = DER) = tbsCertificate.findSubjectAltNames(der)

        @Throws(Asn1Exception::class)
        fun X509TbsCertificate.findSubjectAltNames(der: Der = DER) = extensions?.findSubjectAltNames(der)

        @Throws(Asn1Exception::class)
        fun List<X509CertificateExtension>.findSubjectAltNames(der: Der = DER) =
            runWrappingAs(a = ::Asn1Exception) { find(ObjectIdentifier("2.5.29.17"), der)?.let(::X509GeneralNames) }

        @Throws(Asn1Exception::class)
        fun X509Certificate.findIssuerAltNames(der: Der = DER) = tbsCertificate.findIssuerAltNames(der)

        @Throws(Asn1Exception::class)
        fun X509TbsCertificate.findIssuerAltNames(der: Der = DER) = extensions?.findIssuerAltNames(der)

        @Throws(Asn1Exception::class)
        fun List<X509CertificateExtension>.findIssuerAltNames(der: Der = DER) =
            runWrappingAs(a = ::Asn1Exception) { find(ObjectIdentifier("2.5.29.18"), der)?.let(::X509GeneralNames) }

        private fun List<X509CertificateExtension>.find(oid: ObjectIdentifier, der: Der): List<X509GeneralName>? {
            val matches = filter { it.oid == oid }
            if (matches.size > 1) throw Asn1StructuralException("More than one extension with oid $oid found")
            return matches.singleOrNull()?.let { extension ->
                Asn1Element.parse(extension.value).asSequence().children.map {
                    der.decodeFromTlv(it)
                }
            }
        }
    }
}
