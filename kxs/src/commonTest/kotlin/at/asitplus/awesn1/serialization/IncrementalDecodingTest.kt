@file:OptIn(at.asitplus.awesn1.InternalAwesn1Api::class, kotlinx.serialization.ExperimentalSerializationApi::class)

package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.*
import at.asitplus.awesn1.hardening.IncrementalFixtures
import at.asitplus.awesn1.hardening.InspectingSource
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.*
import kotlinx.serialization.builtins.serializer
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

val IncrementalDecodingTest by matrixSuite {
    "source bridge rejects fourth child without inspecting it" {
        val source = InspectingSource(IncrementalFixtures.fourIntegers, forbiddenFrom = 11)
        val failure = shouldThrow<SerializationException> {
            DER.decodeFromAsn1Source(IncrementalTriple.serializer(), source, 14)
        }
        check(failure.toString().contains("Too many ASN.1 elements"))
        source.committed shouldBe 11
        source.inspected shouldBe 11
    }
    "source bridge agrees with tree and eager byte decoding" {
        val bytes = IncrementalFixtures.threeIntegers
        val expected = IncrementalTriple(1, 2, 3)
        DER.decodeFromAsn1Source(IncrementalTriple.serializer(), bytes.wrapInUnsafeSource(), bytes.size.toLong()) shouldBe expected
        DER.decodeFromTlv(IncrementalTriple.serializer(), Asn1Element.parse(bytes)) shouldBe expected
        val octets = byteArrayOf(4, 9) + bytes.drop(2).toByteArray()
        shouldThrow<SerializationException> { DER.decodeFromAsn1Source(IncrementalTriple.serializer(), octets.wrapInUnsafeSource(), 11) }
    }
    "source bridge enforces exact completion and bounded nested content" {
        listOf("3003020101", "0400").forEach { hex ->
            shouldThrow<SerializationException> {
                DER.decodeFromAsn1Source(EarlyEndingSerializer, hex.hexToByteArray().wrapInUnsafeSource(), 20)
            }
        }
        listOf("300902010102010202010300", "3009020101020102020103020104", "3002020101", "30090201010201020201").forEach { hex ->
            shouldThrow<SerializationException> {
                DER.decodeFromAsn1Source(IncrementalTriple.serializer(), hex.hexToByteArray().wrapInUnsafeSource(), 30)
            }
        }
    }
    "optional nonmatching peeks retain the next value" {
        val bytes = "3003020105".hexToByteArray()
        DER.decodeFromAsn1Source(IncrementalOptional.serializer(), bytes.wrapInUnsafeSource(), 5) shouldBe IncrementalOptional(b = 5)
    }
    "explicit and OCTET wrapper boundaries" {
        val explicit = IncrementalExplicit(ExplicitlyTagged(5))
        val bytes = DER.encodeToByteArray(IncrementalExplicit.serializer(), explicit)
        DER.decodeFromAsn1Source(IncrementalExplicit.serializer(), bytes.wrapInUnsafeSource(), bytes.size.toLong()) shouldBe explicit
        listOf("3008a006020105020106", "3002a000", "3005a003020205").forEach { hex ->
            shouldThrow<SerializationException> {
                DER.decodeFromAsn1Source(IncrementalExplicit.serializer(), hex.hexToByteArray().wrapInUnsafeSource(), 30)
            }
        }
        val serializer = OctetStringEncapsulated.serializer(Int.serializer())
        DER.decodeFromAsn1Source(serializer, "0403020105".hexToByteArray().wrapInUnsafeSource(), 5) shouldBe OctetStringEncapsulated(5)
        listOf("0406020105020106", "0403020205", "0400").forEach { hex ->
            shouldThrow<SerializationException> { DER.decodeFromAsn1Source(serializer, hex.hexToByteArray().wrapInUnsafeSource(), 30) }
        }
    }
    "tree fallback is bounded inside an incremental class" {
        val bytes = "300430023000".hexToByteArray()
        val value = DER.decodeFromAsn1Source(IncrementalOpaque.serializer(), bytes.wrapInUnsafeSource(), 6)
        value.value.derEncoded.toHexString() shouldBe "30023000"
        shouldThrow<SerializationException> {
            DER { maxNestingDepth = 2 }.decodeFromAsn1Source(IncrementalOpaque.serializer(), bytes.wrapInUnsafeSource(), 6)
        }
    }
    "raw bytes bypass speculative ASN.1 and wrappers count toward depth" {
        val raw = "040504033001ff".hexToByteArray()
        DER { maxNestingDepth = 1 }.decodeFromAsn1Source(kotlinx.serialization.builtins.ByteArraySerializer(), raw.wrapInUnsafeSource(), 7).toHexString() shouldBe "04033001ff"
        val serializer = OctetStringEncapsulated.serializer(OctetStringEncapsulated.serializer(Int.serializer()))
        val nested = "04050403020105".hexToByteArray()
        DER { maxNestingDepth = 2 }.decodeFromAsn1Source(serializer, nested.wrapInUnsafeSource(), 7) shouldBe OctetStringEncapsulated(OctetStringEncapsulated(5))
        shouldThrow<SerializationException> { DER { maxNestingDepth = 1 }.decodeFromAsn1Source(serializer, nested.wrapInUnsafeSource(), 7) }
    }
    "primitive-content tag dispatch remains narrowly authorized" {
        val serializer = asn1OpenPolymorphicByTagSerializer<IncrementalSingle>("PrimitiveDispatch") {
            subtype<IncrementalSingle>(Asn1Element.Tag(7u, constructed = false, tagClass = TagClass.CONTEXT_SPECIFIC))
        }
        val bytes = "8703020105".hexToByteArray()
        DER.decodeFromAsn1Source(serializer, bytes.wrapInUnsafeSource(), 5) shouldBe IncrementalSingle(5)
        DER.decodeFromTlv(serializer, Asn1Element.parse(bytes)) shouldBe IncrementalSingle(5)
        shouldThrow<SerializationException> { DER.decodeFromByteArray(IncrementalSingle.serializer(), bytes) }

        val inferred = asn1OpenPolymorphicByTagSerializer<IncrementalInferredTag>("InferredPrimitiveDispatch") {
            subtype<IncrementalInferredTag>(Asn1Element.Tag(7u, constructed = false, tagClass = TagClass.CONTEXT_SPECIFIC))
        }
        DER.decodeFromAsn1Source(inferred, bytes.wrapInUnsafeSource(), 5) shouldBe IncrementalInferredTag(5)
        DER.decodeFromTlv(inferred, Asn1Element.parse(bytes)) shouldBe IncrementalInferredTag(5)

        val primitive = asn1OpenPolymorphicByTagSerializer<IncrementalPrimitiveClass>("RejectedPrimitiveDispatch") {
            subtype<IncrementalPrimitiveClass>(Asn1Element.Tag(7u, constructed = false, tagClass = TagClass.PRIVATE))
        }
        val privateBytes = "c703020105".hexToByteArray()
        shouldThrow<SerializationException> { DER.decodeFromAsn1Source(primitive, privateBytes.wrapInUnsafeSource(), 5) }
        shouldThrow<SerializationException> { DER.decodeFromTlv(primitive, Asn1Element.parse(privateBytes)) }
    }
    "primitive-content tag dispatch preserves tree-dependent class serializers" {
        val serializer = asn1OpenPolymorphicByTagSerializer<IncrementalClassTree>("PrimitiveTreeDispatch") {
            subtype(IncrementalClassTree, setOf(Asn1Element.Tag(7u, false, TagClass.CONTEXT_SPECIFIC))) { true }
        }
        val bytes = "8703020105".hexToByteArray()
        DER.decodeFromAsn1Source(serializer, bytes.wrapInUnsafeSource(), 5) shouldBe IncrementalClassTree(5)
        DER.decodeFromTlv(serializer, Asn1Element.parse(bytes)) shouldBe IncrementalClassTree(5)
        shouldThrow<SerializationException> {
            DER { maxNestingDepth = 1 }.decodeFromAsn1Source(serializer, "87023000".hexToByteArray().wrapInUnsafeSource(), 4)
        }
    }
    "default OID dispatch counts only the actual discriminator and fields" {
        val serializer = asn1OpenPolymorphicByOidSerializer<OpenByOid>("IncrementalOid") {
            subtype<OpenByOidInt>(OpenByOidInt)
            catchAll<OpenByOidRaw>()
        }
        listOf<OpenByOid>(OpenByOidInt(7), OpenByOidRaw(ObjectIdentifier("1.2.3"), "raw")).forEach { value ->
            val bytes = DER.encodeToByteArray(serializer, value)
            DER.decodeFromAsn1Source(serializer, bytes.wrapInUnsafeSource(), bytes.size.toLong()) shouldBe value
        }
        val surplus = Asn1Sequence(listOf(OpenByOidInt.oid.encodeToTlv(), Asn1.Int(7), Asn1.Int(8))).derEncoded
        val source = InspectingSource(surplus, forbiddenFrom = surplus.size - 3)
        shouldThrow<SerializationException> { DER.decodeFromAsn1Source(serializer, source, surplus.size.toLong()) }
        source.committed shouldBe surplus.size - 3
        source.inspected shouldBe surplus.size - 3
        listOf("3000", "3003020101", "300306012a", "3003060180", "310306012a").forEach { hex ->
            shouldThrow<SerializationException> { DER.decodeFromAsn1Source(serializer, hex.hexToByteArray().wrapInUnsafeSource(), 30) }
        }
    }
    "default OID lookahead can select an opaque serializer without consuming its tree" {
        val serializer = asn1OpenPolymorphicByOidSerializer<IncrementalOidTree>("IncrementalOpaqueOid") {
            subtype(IncrementalOidTree::class, IncrementalOidTree, IncrementalOidTree, setOf(Asn1Element.Tag.SEQUENCE))
        }
        val tree = Asn1Sequence(listOf(IncrementalOidTree.oid.encodeToTlv(), Asn1.Int(7)))
        val bytes = tree.derEncoded
        DER.decodeFromAsn1Source(serializer, bytes.wrapInUnsafeSource(), bytes.size.toLong()).tree shouldBe tree
    }
    "custom OID selector receives all children exactly once and decoding uses the cached tree" {
        var calls = 0
        val serializer = asn1OpenPolymorphicByOidSerializer<OpenByOid>("CustomIncrementalOid", oidSelector = { tree ->
            calls++
            val children = tree.asStructure().children
            children.size shouldBe 2
            children.last().asPrimitive().decodeToInt() shouldBe 7
            children.first().asPrimitive().readOid()
        }) { subtype<OpenByOidInt>(OpenByOidInt) }
        val bytes = DER.encodeToByteArray(serializer, OpenByOidInt(7))
        DER.decodeFromAsn1Source(serializer, bytes.wrapInUnsafeSource(), bytes.size.toLong()) shouldBe OpenByOidInt(7)
        calls shouldBe 1
    }
    "compatibility class, surplus, and trailing roots" {
        DER.decodeFromByteArray(IncrementalTriple.serializer(), IncrementalFixtures.threeIntegers) shouldBe IncrementalTriple(1, 2, 3)
        shouldThrow<SerializationException> { DER.decodeFromByteArray(IncrementalTriple.serializer(), IncrementalFixtures.fourIntegers) }
        listOf(byteArrayOf(0), byteArrayOf(2, 1, 4)).forEach { tail ->
            shouldThrow<SerializationException> { DER.decodeFromByteArray(IncrementalTriple.serializer(), IncrementalFixtures.threeIntegers + tail) }
        }
    }
    "primitive tagged ordinary class preserves tree distinction" {
        val tree = DER.encodeToTlv(IncrementalPrimitiveClass.serializer(), IncrementalPrimitiveClass(1))
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
}
