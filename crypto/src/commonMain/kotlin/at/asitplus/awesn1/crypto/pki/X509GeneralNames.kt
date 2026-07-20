// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.awesn1.serialization.Asn1OpenPolymorphicWithDefaultSerializer
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Der
import at.asitplus.awesn1.serialization.ExplicitlyTagged
import at.asitplus.awesn1.serialization.asn1OpenPolymorphicByOidSerializer
import at.asitplus.awesn1.serialization.decodeFromTlv
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Deprecated("Use X509GeneralNames instead", ReplaceWith("X509GeneralNames"))
typealias GeneralNames = X509GeneralNames

/**
 * The RFC 5280 `GeneralName` CHOICE.
 *
 * Closed alternatives retain their ASN.1 payload and expose semantic accessors where useful. The open `otherName` arm
 * delegates its payload to an OID-selected [X509GeneralName.Other.SemanticValue] implementation.
 */
@Serializable
sealed interface X509GeneralName {


    /** The `[0]` GeneralName arm containing an open [SemanticValue] value. */
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

    @Serializable
    @JvmInline
    @Asn1Tag(tagNumber = 1u, constructed = Asn1Tag.ConstructedBit.PRIMITIVE)
    value class Rfc822 private constructor(val rawValue: Asn1String.IA5) : X509GeneralName {
        val value: String get() = rawValue.checkedValue()

        constructor(value: String) : this(Asn1String.IA5(value))
    }

    @Serializable
    @JvmInline
    @Asn1Tag(tagNumber = 2u, constructed = Asn1Tag.ConstructedBit.PRIMITIVE)
    value class Dns private constructor(val rawValue: Asn1String.IA5) : X509GeneralName {
        val value: String get() = rawValue.checkedValue()

        constructor(value: String) : this(Asn1String.IA5(value))
    }

    @Serializable
    @JvmInline
    @Asn1Tag(tagNumber = 3u, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    value class X400Address private constructor(private val rawChildren: List<Asn1Element>) : X509GeneralName {
        val value: Asn1Sequence get() = Asn1.Sequence { rawChildren.forEach { +it } }

        constructor(value: Asn1Sequence) : this(value.children)
    }

    /**
     * `directoryName` is the one explicitly tagged GeneralName alternative. Keeping the wrapper children rawValue here
     * is wire-equivalent to `ExplicitlyTagged<X500Name>`, but postpones validation of the wrapped `Name`.
     */
    @Serializable
    @JvmInline
    @Asn1Tag(tagNumber = 4u, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    value class Directory private constructor(private val rawValueChildren: List<Asn1Element>) : X509GeneralName {
        val value: X500Name
            get() {
                if (rawValueChildren.size != 1)
                    throw Asn1StructuralException("Invalid directoryName: expected one child, got ${rawValueChildren.size}")
                return DER.decodeFromTlv(rawValueChildren.single())
            }

        companion object {
            operator fun invoke(value: X500Name) =
                Directory(listOf(DER.encodeToTlv(X500Name.serializer(), value)))
        }
    }

    @Serializable
    @JvmInline
    @Asn1Tag(tagNumber = 5u, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    value class EdiParty private constructor(private val rawValueChildren: List<Asn1Element>) : X509GeneralName {
        val value: Asn1Sequence get() = Asn1.Sequence { rawValueChildren.forEach { +it } }

        constructor(value: Asn1Sequence) : this(value.children)
    }

    @Serializable
    @JvmInline
    @Asn1Tag(tagNumber = 6u, constructed = Asn1Tag.ConstructedBit.PRIMITIVE)
    value class UniformResourceIdentifier private constructor(val rawValue: Asn1String.IA5) : X509GeneralName {
        val value: String get() = rawValue.checkedValue()

        constructor(value: String) : this(Asn1String.IA5(value))
    }

    @Serializable
    @JvmInline
    @Asn1Tag(tagNumber = 7u, constructed = Asn1Tag.ConstructedBit.PRIMITIVE)
    value class IpAddress private constructor(val rawValue: Asn1OctetString) : X509GeneralName {
        val value: ByteArray get() = rawValue.content

        constructor(value: ByteArray) : this(Asn1OctetString(value))
    }

    @Serializable
    @JvmInline
    @Asn1Tag(tagNumber = 8u, constructed = Asn1Tag.ConstructedBit.PRIMITIVE)
    value class RegisteredId private constructor(val rawValue: Asn1OctetString) : X509GeneralName {
        val value: ObjectIdentifier get() = ObjectIdentifier.decodeFromAsn1ContentBytes(rawValue.content)

        constructor(value: ObjectIdentifier) : this(Asn1OctetString(value.bytes))
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
    }

    companion object {
        private fun Asn1String.IA5.checkedValue(): String {
            if (!isValid) throw Asn1Exception("Malformed IA5String payload")
            return value
        }
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
