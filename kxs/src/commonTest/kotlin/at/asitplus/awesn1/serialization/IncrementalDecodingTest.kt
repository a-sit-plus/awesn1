// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)

package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.*
import at.asitplus.awesn1.hardening.IncrementalFixtures
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlinx.serialization.*
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.builtins.nullable
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*

@Serializable
private data class IncrementalTriple(val a: Int, val b: Int, val c: Int)

@Serializable
@Asn1Tag(7u, Asn1Tag.Class.PRIVATE, Asn1Tag.ConstructedBit.PRIMITIVE)
private data class IncrementalPrimitiveClass(val a: Int)

@Serializable
private data class IncrementalOptional(val a: String? = null, val b: Int)

@Serializable
private data class IncrementalExplicit(
    @Asn1Tag(0u, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED) val value: ExplicitlyTagged<Int>,
)

@Serializable
private data class IncrementalOpaque(val value: Asn1Element)

@Serializable
private data class IncrementalSingle(val value: Int)

@Serializable
@Asn1Tag(7u)
private data class IncrementalInferredTag(val value: Int)

private data class IncrementalOidTree(val tree: Asn1Sequence) : Identifiable, Asn1Encodable<Asn1Sequence> {
    override val oid get() = Companion.oid
    override fun encodeToTlv() = tree
    companion object : Asn1Serializable<Asn1Sequence, IncrementalOidTree>, OidProvider<IncrementalOidTree> {
        override val oid = ObjectIdentifier("1.2.3")
        override val leadingTags = setOf(Asn1Element.Tag.SEQUENCE)
        override fun doDecode(src: Asn1Sequence) = IncrementalOidTree(src)
    }
}

private data class IncrementalClassTree(val value: Int) : Asn1Encodable<Asn1Structure> {
    override fun encodeToTlv() = Asn1Sequence(listOf(Asn1.Int(value)))
    companion object : Asn1Serializable<Asn1Structure, IncrementalClassTree> {
        override val descriptor = buildClassSerialDescriptor("IncrementalClassTree") { element<Int>("value") }
        override val leadingTags = setOf(Asn1Element.Tag.SEQUENCE)
        override fun doDecode(src: Asn1Structure) = IncrementalClassTree(src.children.single().asPrimitive().decodeToInt())
    }
}

private object EarlyEndingSerializer : KSerializer<Unit> {
    override val descriptor = buildClassSerialDescriptor("EarlyEnding") { element<Int>("a") }
    override fun serialize(encoder: Encoder, value: Unit) = error("decode only")
    override fun deserialize(decoder: Decoder) {
        val composite = decoder.beginStructure(descriptor)
        composite.endStructure(descriptor)
    }
}

private object TwoRootsSerializer : KSerializer<Int> {
    override val descriptor = Int.serializer().descriptor
    override fun serialize(encoder: Encoder, value: Int) = error("decode only")
    override fun deserialize(decoder: Decoder): Int {
        val first = decoder.decodeInt()
        val _ = decoder.decodeInt()
        return first
    }
}

val IncrementalDecodingTest by matrixSuite {
    "byte decoding agrees with tree decoding" {
        val bytes = IncrementalFixtures.threeIntegers
        val expected = IncrementalTriple(1, 2, 3)
        DER.decodeFromByteArray(IncrementalTriple.serializer(), bytes) shouldBe expected
        DER.decodeFromTlv(IncrementalTriple.serializer(), Asn1Element.parse(bytes)) shouldBe expected
        val octets = byteArrayOf(4, 9) + bytes.drop(2).toByteArray()
        shouldThrow<SerializationException> { DER.decodeFromByteArray(IncrementalTriple.serializer(), octets) }
    }
    "byte decoding enforces exact completion and bounded nested content" {
        listOf("3003020101", "0400").forEach { hex ->
            shouldThrow<SerializationException> {
                DER.decodeFromByteArray(EarlyEndingSerializer, hex.hexToByteArray())
            }
        }
        listOf("300902010102010202010300", "3009020101020102020103020104", "3002020101", "30090201010201020201").forEach { hex ->
            shouldThrow<SerializationException> {
                DER.decodeFromByteArray(IncrementalTriple.serializer(), hex.hexToByteArray())
            }
        }
    }
    "optional nonmatching peeks retain the next value" {
        val bytes = "3003020105".hexToByteArray()
        DER.decodeFromByteArray(IncrementalOptional.serializer(), bytes) shouldBe IncrementalOptional(b = 5)
    }
    "explicit and OCTET wrapper boundaries" {
        val explicit = IncrementalExplicit(ExplicitlyTagged(5))
        val bytes = DER.encodeToByteArray(IncrementalExplicit.serializer(), explicit)
        DER.decodeFromByteArray(IncrementalExplicit.serializer(), bytes) shouldBe explicit
        listOf("3008a006020105020106", "3002a000", "3005a003020205").forEach { hex ->
            shouldThrow<SerializationException> {
                DER.decodeFromByteArray(IncrementalExplicit.serializer(), hex.hexToByteArray())
            }
        }
        val serializer = OctetStringEncapsulated.serializer(Int.serializer())
        DER.decodeFromByteArray(serializer, "0403020105".hexToByteArray()) shouldBe OctetStringEncapsulated(5)
        listOf("0406020105020106", "0403020205", "0400").forEach { hex ->
            shouldThrow<SerializationException> { DER.decodeFromByteArray(serializer, hex.hexToByteArray()) }
        }
    }
    "empty OCTET retains the supported nullable encapsulated value" {
        val serializer = OctetStringEncapsulated.serializer(Int.serializer().nullable)
        val bytes = "0400".hexToByteArray()
        val expected = OctetStringEncapsulated<Int?>(null)
        DER.decodeFromByteArray(serializer, bytes) shouldBe expected
        DER.decodeFromTlv(serializer, Asn1Element.parse(bytes)) shouldBe expected
    }
    "tree fallback is bounded inside an incremental class" {
        val bytes = "300430023000".hexToByteArray()
        val value = DER.decodeFromByteArray(IncrementalOpaque.serializer(), bytes)
        value.value.derEncoded.toHexString() shouldBe "30023000"
        shouldThrow<SerializationException> {
            DER { maxNestingDepth = 2 }.decodeFromByteArray(IncrementalOpaque.serializer(), bytes)
        }
    }
    "raw bytes bypass speculative ASN.1 and wrappers count toward depth" {
        val raw = "040504033001ff".hexToByteArray()
        DER { maxNestingDepth = 1 }.decodeFromByteArray(kotlinx.serialization.builtins.ByteArraySerializer(), raw).toHexString() shouldBe "04033001ff"
        val serializer = OctetStringEncapsulated.serializer(OctetStringEncapsulated.serializer(Int.serializer()))
        val nested = "04050403020105".hexToByteArray()
        DER { maxNestingDepth = 2 }.decodeFromByteArray(serializer, nested) shouldBe OctetStringEncapsulated(OctetStringEncapsulated(5))
        shouldThrow<SerializationException> { DER { maxNestingDepth = 1 }.decodeFromByteArray(serializer, nested) }
    }
    "primitive-content tag dispatch remains narrowly authorized" {
        val serializer = asn1OpenPolymorphicByTagSerializer<IncrementalSingle>("PrimitiveDispatch") {
            subtype<IncrementalSingle>(Asn1Element.Tag(7u, constructed = false, tagClass = TagClass.CONTEXT_SPECIFIC))
        }
        val bytes = "8703020105".hexToByteArray()
        DER.decodeFromByteArray(serializer, bytes) shouldBe IncrementalSingle(5)
        DER.decodeFromTlv(serializer, Asn1Element.parse(bytes)) shouldBe IncrementalSingle(5)
        shouldThrow<SerializationException> { DER.decodeFromByteArray(IncrementalSingle.serializer(), bytes) }

        val inferred = asn1OpenPolymorphicByTagSerializer<IncrementalInferredTag>("InferredPrimitiveDispatch") {
            subtype<IncrementalInferredTag>(Asn1Element.Tag(7u, constructed = false, tagClass = TagClass.CONTEXT_SPECIFIC))
        }
        DER.decodeFromByteArray(inferred, bytes) shouldBe IncrementalInferredTag(5)
        DER.decodeFromTlv(inferred, Asn1Element.parse(bytes)) shouldBe IncrementalInferredTag(5)

        val primitive = asn1OpenPolymorphicByTagSerializer<IncrementalPrimitiveClass>("RejectedPrimitiveDispatch") {
            subtype<IncrementalPrimitiveClass>(Asn1Element.Tag(7u, constructed = false, tagClass = TagClass.PRIVATE))
        }
        val privateBytes = "c703020105".hexToByteArray()
        shouldThrow<SerializationException> { DER.decodeFromByteArray(primitive, privateBytes) }
        shouldThrow<SerializationException> { DER.decodeFromTlv(primitive, Asn1Element.parse(privateBytes)) }
    }
    "primitive-content tag dispatch preserves tree-dependent class serializers" {
        val serializer = asn1OpenPolymorphicByTagSerializer<IncrementalClassTree>("PrimitiveTreeDispatch") {
            subtype(IncrementalClassTree, setOf(Asn1Element.Tag(7u, false, TagClass.CONTEXT_SPECIFIC))) { true }
        }
        val bytes = "8703020105".hexToByteArray()
        DER.decodeFromByteArray(serializer, bytes) shouldBe IncrementalClassTree(5)
        DER.decodeFromTlv(serializer, Asn1Element.parse(bytes)) shouldBe IncrementalClassTree(5)
        shouldThrow<SerializationException> {
            DER { maxNestingDepth = 1 }.decodeFromByteArray(serializer, "87023000".hexToByteArray())
        }
    }
    "default OID dispatch counts only the actual discriminator and fields" {
        val serializer = asn1OpenPolymorphicByOidSerializer<OpenByOid>("IncrementalOid") {
            subtype<OpenByOidInt>(OpenByOidInt)
            catchAll<OpenByOidRaw>()
        }
        listOf<OpenByOid>(OpenByOidInt(7), OpenByOidRaw(ObjectIdentifier("1.2.3"), "raw")).forEach { value ->
            val bytes = DER.encodeToByteArray(serializer, value)
            DER.decodeFromByteArray(serializer, bytes) shouldBe value
        }
        val surplus = Asn1Sequence(listOf(OpenByOidInt.oid.encodeToTlv(), Asn1.Int(7), Asn1.Int(8))).derEncoded
        shouldThrow<SerializationException> {
            DER.decodeFromByteArray(serializer, surplus)
        }.message shouldContain "Too many ASN.1 elements"
        listOf("3000", "3003020101", "300306012a", "3003060180", "310306012a").forEach { hex ->
            shouldThrow<SerializationException> { DER.decodeFromByteArray(serializer, hex.hexToByteArray()) }
        }
    }
    "default OID lookahead can select an opaque serializer without consuming its tree" {
        val serializer = asn1OpenPolymorphicByOidSerializer<IncrementalOidTree>("IncrementalOpaqueOid") {
            subtype(IncrementalOidTree::class, IncrementalOidTree, IncrementalOidTree, setOf(Asn1Element.Tag.SEQUENCE))
        }
        val tree = Asn1Sequence(listOf(IncrementalOidTree.oid.encodeToTlv(), Asn1.Int(7)))
        val bytes = tree.derEncoded
        DER.decodeFromByteArray(serializer, bytes).tree shouldBe tree
    }
    "OID SET input is rejected" {
        val bytes = Asn1Set(listOf(OpenByOidInt.oid.encodeToTlv(), Asn1.Int(7))).derEncoded
        val serializer = asn1OpenPolymorphicByOidSerializer<OpenByOid>("SetRejected") {
            subtype<OpenByOidInt>(OpenByOidInt)
        }
        shouldThrow<SerializationException> { DER.decodeFromByteArray(serializer, bytes) }.message shouldContain "SET"
        shouldThrow<SerializationException> { DER.decodeFromTlv(serializer, Asn1Element.parse(bytes)) }.message shouldContain "SET"
    }
    "compatibility class, surplus, and trailing roots" {
        DER.decodeFromByteArray(IncrementalTriple.serializer(), IncrementalFixtures.threeIntegers) shouldBe IncrementalTriple(1, 2, 3)
        shouldThrow<SerializationException> { DER.decodeFromByteArray(IncrementalTriple.serializer(), IncrementalFixtures.fourIntegers) }
        listOf(byteArrayOf(0), byteArrayOf(2, 1, 4)).forEach { tail ->
            shouldThrow<SerializationException> { DER.decodeFromByteArray(IncrementalTriple.serializer(), IncrementalFixtures.threeIntegers + tail) }
        }
    }
    "primitive tagged ordinary class preserves tree distinction" {
        val tree = Asn1CustomStructure.asPrimitive(listOf(Asn1.Int(1)), 7u, TagClass.PRIVATE)
        DER.decodeFromTlv(IncrementalPrimitiveClass.serializer(), tree) shouldBe IncrementalPrimitiveClass(1)
        shouldThrow<SerializationException> { DER.decodeFromByteArray(IncrementalPrimitiveClass.serializer(), tree.derEncoded) }
    }
    "raw OCTET bytes stay arbitrary and empty OCTET is not a class" {
        listOf("3000", "3003020201", "1f81", "").forEach { hex ->
            val bytes = hex.hexToByteArray()
            DER.decodeFromByteArray(kotlinx.serialization.builtins.ByteArraySerializer(), byteArrayOf(4, bytes.size.toByte()) + bytes).toList() shouldBe bytes.toList()
        }
        shouldThrow<SerializationException> { DER.decodeFromByteArray(EarlyEndingSerializer, byteArrayOf(4, 0)) }
    }
    "custom serializer cannot end with unread children" {
        shouldThrow<SerializationException> { DER.decodeFromByteArray(EarlyEndingSerializer, "3003020101".hexToByteArray()) }
    }
    "custom serializer cannot consume a second root" {
        val bytes = "020101020102".hexToByteArray()
        shouldThrow<SerializationException> {
            DER.decodeFromByteArray(TwoRootsSerializer, bytes)
        }.message shouldContain "direct-child limit"
    }
}
