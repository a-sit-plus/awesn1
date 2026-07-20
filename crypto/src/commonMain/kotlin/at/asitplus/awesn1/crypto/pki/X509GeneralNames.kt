// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.ExplicitlyTagged
import at.asitplus.awesn1.serialization.asn1OpenPolymorphicByTagSerializer
import at.asitplus.awesn1.serialization.decodeFromTlv
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.modules.SerializersModule
import kotlin.jvm.JvmInline

@Deprecated("Use X509GeneralNames instead", ReplaceWith("X509GeneralNames"))
typealias GeneralNames = X509GeneralNames

/**
 * The RFC 5280 `GeneralName` CHOICE.
 *
 * Every alternative retains its rawValue ASN.1 payload. Semantic accessors decode that payload only when requested and
 * may therefore throw, allowing structurally recognizable but malformed names to round-trip losslessly.
 */
@Serializable
sealed interface X509GeneralName<T> {

    val value: T

    @Serializable(with = X509OtherNameRawSerializer::class)
    @Asn1Tag(tagNumber = 0u, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    open class Other<T> private constructor(
        internal val fallbackOid: ObjectIdentifier?,
        internal val fallbackValue: Asn1Element?,
        @Suppress("UNUSED_PARAMETER") marker: Unit,
    ) :
        X509GeneralName<T>, Identifiable {
        protected constructor() : this(null, null, Unit)

        override open val oid: ObjectIdentifier
            get() = checkNotNull(fallbackOid) { "A specialized otherName must override oid" }
        val typeId: ObjectIdentifier get() = oid

        @Suppress("UNCHECKED_CAST")
        override open val value: T
            get() = checkNotNull(fallbackValue) { "A specialized otherName must override value" } as T

        constructor(typeId: ObjectIdentifier, value: T) : this(
            typeId,
            value as? Asn1Element
                ?: throw IllegalArgumentException("The generic otherName fallback requires an Asn1Element value"),
            Unit,
        )

        companion object {
            internal fun <T> fromRaw(oid: ObjectIdentifier, value: Asn1Element) = Other<T>(oid, value, Unit)
        }

        override fun equals(other: Any?): Boolean =
            this === other || this::class == Other::class && other is Other<*> &&
                    fallbackOid == other.fallbackOid && fallbackValue == other.fallbackValue

        override fun hashCode(): Int = fallbackOid?.let { 31 * it.hashCode() + fallbackValue.hashCode() } ?: super.hashCode()

        override fun toString(): String = fallbackOid?.let { "OtherName(oid=$it, value=$fallbackValue)" } ?: super.toString()
    }

    @Serializable
    @JvmInline
    @Asn1Tag(tagNumber = 1u, constructed = Asn1Tag.ConstructedBit.PRIMITIVE)
    value class Rfc822 private constructor(val rawValue: Asn1String.IA5) : X509GeneralName<String> {
        override val value: String get() = rawValue.checkedValue()

        constructor(value: String) : this(Asn1String.IA5(value))
    }

    @Serializable
    @JvmInline
    @Asn1Tag(tagNumber = 2u, constructed = Asn1Tag.ConstructedBit.PRIMITIVE)
    value class Dns private constructor(val rawValue: Asn1String.IA5) : X509GeneralName<String> {
        override val value: String get() = rawValue.checkedValue()

        constructor(value: String) : this(Asn1String.IA5(value))
    }

    @Serializable
    @JvmInline
    @Asn1Tag(tagNumber = 3u, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    value class X400Address private constructor(private val rawChildren: List<Asn1Element>) :
        X509GeneralName<Asn1Sequence> {
        override val value: Asn1Sequence get() = Asn1.Sequence { rawChildren.forEach { +it } }

        constructor(value: Asn1Sequence) : this(value.children)
    }

    /**
     * `directoryName` is the one explicitly tagged GeneralName alternative. Keeping the wrapper children rawValue here
     * is wire-equivalent to `ExplicitlyTagged<X500Name>`, but postpones validation of the wrapped `Name`.
     */
    @Serializable
    @JvmInline
    @Asn1Tag(tagNumber = 4u, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    value class Directory private constructor(private val rawValueChildren: List<Asn1Element>) :
        X509GeneralName<X500Name> {
        override val value: X500Name
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
    value class EdiParty private constructor(private val rawValueChildren: List<Asn1Element>) :
        X509GeneralName<Asn1Sequence> {
        override val value: Asn1Sequence get() = Asn1.Sequence { rawValueChildren.forEach { +it } }

        constructor(value: Asn1Sequence) : this(value.children)
    }

    @Serializable
    @JvmInline
    @Asn1Tag(tagNumber = 6u, constructed = Asn1Tag.ConstructedBit.PRIMITIVE)
    value class UniformResourceIdentifier private constructor(val rawValue: Asn1String.IA5) :
        X509GeneralName<String> {
        override val value: String get() = rawValue.checkedValue()

        constructor(value: String) : this(Asn1String.IA5(value))
    }

    @Serializable
    @JvmInline
    @Asn1Tag(tagNumber = 7u, constructed = Asn1Tag.ConstructedBit.PRIMITIVE)
    value class IpAddress private constructor(val rawValue: Asn1OctetString) : X509GeneralName<ByteArray> {
        override val value: ByteArray get() = rawValue.content

        constructor(value: ByteArray) : this(Asn1OctetString(value))
    }

    @Serializable
    @JvmInline
    @Asn1Tag(tagNumber = 8u, constructed = Asn1Tag.ConstructedBit.PRIMITIVE)
    value class RegisteredId private constructor(val rawValue: Asn1OctetString) :
        X509GeneralName<ObjectIdentifier> {
        override val value: ObjectIdentifier get() = ObjectIdentifier.decodeFromAsn1ContentBytes(rawValue.content)

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

@Serializable
@Asn1Tag(tagNumber = 0u, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
private data class RawX509OtherName(
    val oid: ObjectIdentifier,
    @Asn1Tag(tagNumber = 0u, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    val value: ExplicitlyTagged<Asn1Element>,
)

/** Raw, lossless fallback serializer for an unrecognized `otherName` OID. */
class X509OtherNameRawSerializer<T>(@Suppress("UNUSED_PARAMETER") typeSerializer: KSerializer<T>) :
    KSerializer<X509GeneralName.Other<T>> {
    private val fallback = RawX509OtherName.serializer()

    override val descriptor = fallback.descriptor

    override fun serialize(encoder: Encoder, value: X509GeneralName.Other<T>) {
        val oid = value.fallbackOid
            ?: throw SerializationException("The raw otherName serializer cannot encode ${value::class.simpleName}")
        val rawValue = value.fallbackValue
            ?: throw SerializationException("The raw otherName serializer cannot encode ${value::class.simpleName}")
        encoder.encodeSerializableValue(fallback, RawX509OtherName(oid, ExplicitlyTagged(rawValue)))
    }

    override fun deserialize(decoder: Decoder): X509GeneralName.Other<T> {
        val decoded = decoder.decodeSerializableValue(fallback)
        return X509GeneralName.Other.fromRaw(decoded.oid, decoded.value.value)
    }
}

/** Selects configured OID semantics, or the raw fallback when no OID module is installed. */
private class X509OtherNameDispatchSerializer<T>(private val typeSerializer: KSerializer<T>) :
    KSerializer<X509GeneralName.Other<T>> {
    private val fallback = X509OtherNameRawSerializer(typeSerializer)

    override val descriptor = fallback.descriptor

    @Suppress("UNCHECKED_CAST")
    private fun SerializersModule.configuredSerializer(): KSerializer<X509GeneralName.Other<T>>? =
        getContextual(X509GeneralName.Other::class, listOf(typeSerializer))
                as KSerializer<X509GeneralName.Other<T>>?

    override fun serialize(encoder: Encoder, value: X509GeneralName.Other<T>) =
        encoder.encodeSerializableValue(encoder.serializersModule.configuredSerializer() ?: fallback, value)

    override fun deserialize(decoder: Decoder): X509GeneralName.Other<T> =
        decoder.decodeSerializableValue(decoder.serializersModule.configuredSerializer() ?: fallback)
}

@Suppress("UNCHECKED_CAST")
private val X509GeneralNameSerializer: KSerializer<X509GeneralName<*>> =
    asn1OpenPolymorphicByTagSerializer(serialName = "X509GeneralName") {
        subtype(
            serializer = X509OtherNameDispatchSerializer(Asn1Element.serializer()) as KSerializer<X509GeneralName<*>>,
            leadingTags = setOf(X509GeneralName.Tags.otherName),
            matches = { it is X509GeneralName.Other<*> },
        )
        subtype(X509GeneralName.Rfc822.serializer(), setOf(X509GeneralName.Tags.rfc822Name)) {
            it is X509GeneralName.Rfc822
        }
        subtype(X509GeneralName.Dns.serializer(), setOf(X509GeneralName.Tags.dnsName)) {
            it is X509GeneralName.Dns
        }
        subtype(X509GeneralName.X400Address.serializer(), setOf(X509GeneralName.Tags.x400Address)) {
            it is X509GeneralName.X400Address
        }
        subtype(X509GeneralName.Directory.serializer(), setOf(X509GeneralName.Tags.directoryName)) {
            it is X509GeneralName.Directory
        }
        subtype(X509GeneralName.EdiParty.serializer(), setOf(X509GeneralName.Tags.ediPartyName)) {
            it is X509GeneralName.EdiParty
        }
        subtype(
            X509GeneralName.UniformResourceIdentifier.serializer(),
            setOf(X509GeneralName.Tags.uniformResourceIdentifier),
        ) { it is X509GeneralName.UniformResourceIdentifier }
        subtype(X509GeneralName.IpAddress.serializer(), setOf(X509GeneralName.Tags.ipAddress)) {
            it is X509GeneralName.IpAddress
        }
        subtype(X509GeneralName.RegisteredId.serializer(), setOf(X509GeneralName.Tags.registeredID)) {
            it is X509GeneralName.RegisteredId
        }
    }

/** Adapts the heterogeneous collection through tag-polymorphic CHOICE dispatch. */
internal object X509GeneralNamesSerializer : KSerializer<X509GeneralNames> {
    private val delegate = ListSerializer(X509GeneralNameSerializer)

    override val descriptor = delegate.descriptor

    override fun serialize(encoder: Encoder, value: X509GeneralNames) = delegate.serialize(encoder, value.entries)

    override fun deserialize(decoder: Decoder) = X509GeneralNames(delegate.deserialize(decoder))
}

/** `GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName`. */
@JvmInline
@Serializable(with = X509GeneralNamesSerializer::class)
value class X509GeneralNames @Throws(Throwable::class) constructor(
    val entries: List<X509GeneralName<*>>
) {
    val dnsNames: List<String> get() = entries.filterIsInstance<X509GeneralName.Dns>().map { it.value }
    val rfc822Names: List<String> get() = entries.filterIsInstance<X509GeneralName.Rfc822>().map { it.value }
    val uris: List<String>
        get() = entries.filterIsInstance<X509GeneralName.UniformResourceIdentifier>().map { it.value }
    val ipAddresses: List<ByteArray> get() = entries.filterIsInstance<X509GeneralName.IpAddress>().map { it.value }
    val directoryNames: List<X500Name>
        get() = entries.filterIsInstance<X509GeneralName.Directory>().map { it.value }
    val otherNames: List<X509GeneralName.Other<*>>
        get() = entries.filterIsInstance<X509GeneralName.Other<*>>()

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

        private fun List<X509CertificateExtension>.find(oid: ObjectIdentifier): List<X509GeneralName<*>>? {
            val matches = filter { it.oid == oid }
            if (matches.size > 1) throw Asn1StructuralException("More than one extension with oid $oid found")
            return matches.singleOrNull()?.let { extension ->
                Asn1Element.parse(extension.value).asSequence().children.map {
                    DER.decodeFromTlv(X509GeneralNameSerializer, it)
                }
            }
        }
    }
}
