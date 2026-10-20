// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(ExperimentalSerializationApi::class, ExperimentalStdlibApi::class)

package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1OctetString
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlin.jvm.JvmInline
import kotlinx.serialization.Contextual
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

// Suite names preserve the original finding identifiers.
@Serializable
private data class GlOctetPrimitive(
    @Asn1Tag(tagNumber = 1uL, constructed = Asn1Tag.ConstructedBit.PRIMITIVE) val b: ByteArray,
) {
    override fun equals(other: Any?) = other is GlOctetPrimitive && b.contentEquals(other.b)
    override fun hashCode() = b.contentHashCode()
}

@Serializable
private data class GlOctetConstructed(
    @Asn1Tag(tagNumber = 1uL, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED) val b: ByteArray,
) {
    override fun equals(other: Any?) = other is GlOctetConstructed && b.contentEquals(other.b)
    override fun hashCode() = b.contentHashCode()
}

val bytearray_constructed_tag_dropped_own_output_rejected by matrixSuite {
    "A primitive-tagged byte array round-trips" {
        val ok = GlOctetPrimitive(byteArrayOf(9, 9))
        DER.roundTrip<GlOctetPrimitive>(ok) shouldBe ok
    }

    "A constructed tag on a byte array is rejected" {
        shouldThrow<SerializationException> {
            DER.encodeToByteArray(GlOctetConstructed(byteArrayOf(9, 9)))
        }
    }
}

@Serializable
private data class GlConstructedTaggedBytes(
    @Asn1Tag(tagNumber = 0uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    val bytes: ByteArray,
) {
    override fun equals(other: Any?) = other is GlConstructedTaggedBytes && bytes.contentEquals(other.bytes)
    override fun hashCode() = bytes.contentHashCode()
}

@Serializable
private data class GlConstructedTaggedInt(
    @Asn1Tag(tagNumber = 0uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    val n: Int,
)

val constructed_tag_template_primitive_valued_silently_undecodable by matrixSuite {
    "A constructed tag on byte-array content is rejected" {
        shouldThrow<SerializationException> {
            DER.encodeToByteArray(GlConstructedTaggedBytes(byteArrayOf(1, 2, 3)))
        }
    }

    "A constructed tag on integer content is rejected" {
        shouldThrow<SerializationException> {
            DER.encodeToByteArray(GlConstructedTaggedInt(7))
        }
    }
}

private enum class GlConstructedMode { OFF, ON }

@Serializable
private data class GlConstructedEnumHost(
    @Asn1Tag(tagNumber = 2uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    val m: GlConstructedMode,
)

val enum_constructed_bit_roundtrip_v2 by matrixSuite {
    "A constructed tag on an enum is rejected" {
        shouldThrow<SerializationException> {
            DER.encodeToByteArray(GlConstructedEnumHost(GlConstructedMode.OFF))
        }
    }
}

@Serializable
private data class GlInner(val a: Int)

@Serializable
private data class GlConsTaggedHolder(
    @Asn1Tag(tagNumber = 0uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    val x: GlInner,
)

@Serializable
private data class GlPrimTaggedHolder(
    @Asn1Tag(tagNumber = 0uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC, constructed = Asn1Tag.ConstructedBit.PRIMITIVE)
    val x: GlInner,
)

val primitive_constructed_hint_structure_undecodable by matrixSuite {
    "A constructed-tagged structure round-trips" {
        val ok = GlConsTaggedHolder(GlInner(5))
        DER.roundTrip<GlConsTaggedHolder>(ok) shouldBe ok
    }

    "A primitive tag on a structure is rejected" {
        shouldThrow<SerializationException> {
            DER.encodeToByteArray(GlPrimTaggedHolder(GlInner(5)))
        }
    }
}

@Serializable
private data class GlHostRetaggedConstructed(
    @Asn1Tag(tagNumber = 0uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    val wrapped: OctetStringEncapsulated<Int>,
)

@Serializable
private data class GlHostRetaggedInfer(
    @Asn1Tag(tagNumber = 0uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC)
    val wrapped: OctetStringEncapsulated<Int>,
)

val octetwrapper_retag_primitive_leak_v2 by matrixSuite {
    "An octet wrapper with a constructed tag override round-trips" {
        val pinned = GlHostRetaggedConstructed(OctetStringEncapsulated(5))
        DER.roundTrip<GlHostRetaggedConstructed>(pinned) shouldBe pinned
    }

    "An octet wrapper with an inferred constructed bit round-trips" {
        val infer = GlHostRetaggedInfer(OctetStringEncapsulated(5))
        DER.roundTrip<GlHostRetaggedInfer>(infer) shouldBe infer
    }
}

private enum class GlMode { OFF, ON }

@Serializable
@JvmInline
private value class GlPlainEnumHolder(val e: GlMode)

@Serializable
@Asn1Tag(tagNumber = 7uL, tagClass = Asn1Tag.Class.APPLICATION)
@JvmInline
private value class GlTaggedEnumHolder(val e: GlMode)

@Serializable
private data class GlPlainHolderHost(val a: GlPlainEnumHolder, val b: Int)

@Serializable
private data class GlTaggedHolderHost(val a: GlTaggedEnumHolder, val b: Int)

val encodeenum_inline_tag_dropped by matrixSuite {
    "An untagged enum-backed value class round-trips" {
        val plain = GlPlainHolderHost(GlPlainEnumHolder(GlMode.ON), 5)
        DER.roundTrip<GlPlainHolderHost>(plain) shouldBe plain
    }

    "A tagged enum-backed value class retains its APPLICATION tag and round-trips" {
        val tagged = GlTaggedHolderHost(GlTaggedEnumHolder(GlMode.ON), 5)
        DER.encodeToByteArray(tagged).toHexString() shouldBe "3006470101020105"
        DER.roundTrip<GlTaggedHolderHost>(tagged) shouldBe tagged
    }
}

@Serializable
@JvmInline
private value class GlToken(val value: Int)

private object GlTokenSerializer : KSerializer<GlToken> {
    override val descriptor: SerialDescriptor =
        GlToken.serializer().descriptor.withAsn1LeadingTags(setOf(Asn1Element.Tag.STRING_UTF8))

    override fun serialize(encoder: Encoder, value: GlToken) = encoder.encodeString(value.value.toString())
    override fun deserialize(decoder: Decoder): GlToken = GlToken(decoder.decodeString().toInt())
}

@Serializable
private data class GlP4(
    @Serializable(with = GlTokenSerializer::class) val t: GlToken? = null,
    val note: String = "",
)

val inline_declared_leading_tags_dropped by matrixSuite {
    "Declared leading tags on an inline serializer expose an ambiguous layout" {
        val der = DER { encodeDefaults = false }
        shouldThrow<SerializationException> {
            der.encodeToByteArray(GlP4(GlToken(7)))
        }
    }
}

@Serializable
private data class DsRawTagPlain(
    @Asn1Tag(tagNumber = 0uL, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    val e: Asn1Element,
)

@Serializable
private data class DsRawTagContextual(
    @Asn1Tag(tagNumber = 0uL, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    @Contextual
    val e: Asn1Element,
)

val derenv_rawtag_contextual_bypass by matrixSuite {
    val octet = Asn1.OctetString(byteArrayOf(1, 2))

    "A tag override on a raw element is rejected" {
        shouldThrow<SerializationException> {
            DER.encodeToByteArray(DsRawTagPlain(octet))
        }
    }

    "A tag override on a contextual raw element is also rejected" {
        shouldThrow<SerializationException> {
            DER.encodeToByteArray(DsRawTagContextual(octet))
        }
    }
}

@Serializable
private data class GlByteArrayHolder(val os: ByteArray) {
    override fun equals(other: Any?) = other is GlByteArrayHolder && os.contentEquals(other.os)
    override fun hashCode() = os.contentHashCode()
}

@Serializable
private data class GlOctetStringHolder(val os: Asn1OctetString)

val asn1octetstring_any_tag_acceptance by matrixSuite {
    val integerWhereOctetStringDeclared = "3003020105".hexToByteArray()

    "An INTEGER cannot decode as a ByteArray property" {
        shouldThrow<SerializationException> {
            DER.decodeFromByteArray<GlByteArrayHolder>(integerWhereOctetStringDeclared)
        }
    }

    "An INTEGER cannot decode as an Asn1OctetString property" {
        shouldThrow<SerializationException> {
            DER.decodeFromByteArray<GlOctetStringHolder>(integerWhereOctetStringDeclared)
        }
    }
}

@Serializable
private data class GlBothContext(
    @Asn1Tag(tagNumber = 5uL) val a: String? = null,
    @Asn1Tag(tagNumber = 5uL) val b: Int? = null,
)

@Serializable
private data class GlInferClass(
    @Asn1Tag(tagNumber = 5uL, tagClass = Asn1Tag.Class.INFER) val a: String? = null,
    @Asn1Tag(tagNumber = 5uL) val b: Int? = null,
)

val asn1tag_infer_class_ambiguity_mispredict by matrixSuite {
    "Colliding explicit context-specific tags are rejected" {
        shouldThrow<SerializationException> {
            DER.encodeToByteArray(GlBothContext(a = "ab"))
        }
    }

    "An inferred tag class does not hide a context-specific collision" {
        shouldThrow<SerializationException> {
            DER.encodeToByteArray(GlInferClass(a = "ab"))
        }
    }
}

private inline fun <reified T> Der.roundTrip(value: T): T = decodeFromByteArray(encodeToByteArray(value))
