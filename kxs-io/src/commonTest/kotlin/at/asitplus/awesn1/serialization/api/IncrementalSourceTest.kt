// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)

package at.asitplus.awesn1.serialization.api

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.serialization.asn1OpenPolymorphicByOidSerializer
import at.asitplus.awesn1.hardening.IncrementalFixtures
import at.asitplus.awesn1.io.decodeFromSource
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.awesn1.serialization.OctetStringEncapsulated
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import kotlinx.serialization.*
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.PairSerializer
import kotlinx.serialization.builtins.nullable
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*

@Serializable
private data class SourceTriple(val a: Int, val b: Int, val c: Int)

@Serializable
@Asn1Tag(17u, Asn1Tag.Class.UNIVERSAL, Asn1Tag.ConstructedBit.CONSTRUCTED)
private data class SourceSetTriple(val a: Int, val b: Int, val c: Int)

@Serializable
@Asn1Tag(0u, Asn1Tag.Class.CONTEXT_SPECIFIC, Asn1Tag.ConstructedBit.CONSTRUCTED)
private data class SourceContextTriple(val a: Int, val b: Int, val c: Int)

@Serializable
@Asn1Tag(0u, Asn1Tag.Class.APPLICATION, Asn1Tag.ConstructedBit.CONSTRUCTED)
private data class SourceApplicationTriple(val a: Int, val b: Int, val c: Int)

@Serializable
@Asn1Tag(201u, Asn1Tag.Class.PRIVATE, Asn1Tag.ConstructedBit.CONSTRUCTED)
private data class SourcePrivateTriple(val a: Int, val b: Int, val c: Int)

@Serializable
private data class SourceNested(val value: SourceTriple, val sibling: Int)

@Serializable
private data class SourceOctetViews(
    val note: String? = null,
    val raw: ByteArray,
    val wrapped: OctetStringEncapsulated<Int>,
    val after: Int,
)

private object UnreadSourceSerializer : KSerializer<Unit> {
    override val descriptor = buildClassSerialDescriptor("UnreadSource") { element<Int>("a") }
    override fun serialize(encoder: Encoder, value: Unit) = error("decode only")
    override fun deserialize(decoder: Decoder) {
        decoder.beginStructure(descriptor).endStructure(descriptor)
    }
}

private object RetryAfterUnreadSourceSerializer : KSerializer<Unit> {
    override val descriptor = buildClassSerialDescriptor("RetryAfterUnreadSource") { element<Int>("a") }
    override fun serialize(encoder: Encoder, value: Unit) = error("decode only")
    override fun deserialize(decoder: Decoder) {
        val fields = decoder.beginStructure(descriptor)
        try { fields.endStructure(descriptor) } catch (_: IllegalStateException) { }
        val _ = fields.decodeIntElement(descriptor, 0)
        fields.endStructure(descriptor)
    }
}

private object TwoSourceRootsSerializer : KSerializer<Int> {
    override val descriptor = Int.serializer().descriptor
    override fun serialize(encoder: Encoder, value: Int) = error("decode only")
    override fun deserialize(decoder: Decoder): Int {
        val first = decoder.decodeInt()
        val _ = decoder.decodeInt()
        return first
    }
}

val IncrementalSourceTest by matrixSuite {
    listOf(
        Triple("30", SourceTriple.serializer(), SourceTriple(1, 2, 3)),
        Triple("31", SourceSetTriple.serializer(), SourceSetTriple(1, 2, 3)),
        Triple("a0", SourceContextTriple.serializer(), SourceContextTriple(1, 2, 3)),
        Triple("60", SourceApplicationTriple.serializer(), SourceApplicationTriple(1, 2, 3)),
        Triple("ff8149", SourcePrivateTriple.serializer(), SourcePrivateTriple(1, 2, 3)),
    ).forEach { (tag, serializer, expected) ->
        val fields = "020101020102020103"

        "structure $tag accepts exactly its declared fields" {
            val source = Buffer().apply { write("${tag}09$fields".hexToByteArray()) }
            DER.decodeFromSource(serializer, source) shouldBe expected
            source.exhausted() shouldBe true
        }

        "structure $tag rejects surplus children before their headers at root and nested levels" {
            listOf("020104", "1f81", "0281", "028180").forEach { surplus ->
                val content = fields + surplus
                val encoded = "$tag${(content.length / 2).toString(16).padStart(2, '0')}$content"
                val source = Buffer().apply { write(encoded.hexToByteArray()) }
                shouldThrow<SerializationException> {
                    DER.decodeFromSource(serializer, source)
                }.message shouldContain "Too many ASN.1 elements"
                source.readByteArray().toHexString() shouldBe surplus

                val nestedContent = encoded + "020109"
                val nested = Buffer().apply {
                    write("30${(nestedContent.length / 2).toString(16).padStart(2, '0')}$nestedContent".hexToByteArray())
                }
                shouldThrow<SerializationException> {
                    DER.decodeFromSource(PairSerializer(serializer, Int.serializer()), nested)
                }.message shouldContain "Too many ASN.1 elements"
                nested.readByteArray().toHexString() shouldBe surplus + "020109"
            }
        }

        "structure $tag shares the enclosing structure's depth budget" {
            val content = "${tag}09${fields}020109"
            val bytes = "30${(content.length / 2).toString(16).padStart(2, '0')}$content".hexToByteArray()
            val nestedSerializer = PairSerializer(serializer, Int.serializer())
            val complete = Buffer().apply { write(bytes) }
            DER { maxNestingDepth = 2 }.decodeFromSource(nestedSerializer, complete) shouldBe (expected to 9)
            complete.exhausted() shouldBe true

            val source = Buffer().apply { write(bytes) }
            shouldThrow<SerializationException> {
                DER { maxNestingDepth = 1 }.decodeFromSource(nestedSerializer, source)
            }.message shouldContain "depth"
            source.readByteArray().toHexString() shouldBe content
        }

        "structure $tag cannot borrow child header or payload bytes from its sibling" {
            listOf("021f81", "020281", "03020205").forEach { malformed ->
                val content = tag + malformed + "020109"
                val source = Buffer().apply {
                    write("30${(content.length / 2).toString(16).padStart(2, '0')}$content".hexToByteArray())
                }
                shouldThrow<SerializationException> {
                    DER.decodeFromSource(PairSerializer(serializer, Int.serializer()), source)
                }
                source.readByteArray().toHexString() shouldBe malformed.drop(2) + "020109"
            }
        }
    }

    "optional peeks distinguish adjacent raw and encapsulating OCTETs and preserve their sibling" {
        val source = Buffer().apply { write("300d04030201050403020105020109".hexToByteArray()) }
        val value = DER.decodeFromSource<SourceOctetViews>(source)
        value.note shouldBe null
        value.raw.toHexString() shouldBe "020105"
        value.wrapped shouldBe OctetStringEncapsulated(5)
        value.after shouldBe 9
        source.exhausted() shouldBe true
    }
    "surplus content inside an OCTET is rejected before its header and following sibling are consumed" {
        listOf(
            "301004030201050406020105020106020109" to "020106",
            "300f040302010504050201051f81020109" to "1f81",
            "300f040302010504050201050281020109" to "0281",
        ).forEach { (hex, surplus) ->
            val source = Buffer().apply { write(hex.hexToByteArray()) }
            shouldThrow<SerializationException> {
                DER.decodeFromSource<SourceOctetViews>(source)
            }.message shouldContain "Too many ASN.1 elements"
            source.readByteArray().toHexString() shouldBe surplus + "020109"
        }
    }
    "an encapsulated child cannot borrow payload bytes from the OCTET's following sibling" {
        val source = Buffer().apply { write("300d04030201050403020205020109".hexToByteArray()) }
        shouldThrow<SerializationException> { DER.decodeFromSource<SourceOctetViews>(source) }
        source.readByteArray().toHexString() shouldBe "020205020109"
    }
    "surplus children are rejected before parsing their headers and remain unread" {
        val fields = IncrementalFixtures.threeIntegers.copyOfRange(2, 11)
        listOf("020104", "1f81", "0281", "028180").forEach { hex ->
            val tail = hex.hexToByteArray()
            val sequence = byteArrayOf(0x30, (fields.size + tail.size).toByte()) + fields + tail
            val source = Buffer().apply { write(sequence) }
            shouldThrow<SerializationException> {
                DER.decodeFromSource<SourceTriple>(source)
            }.message shouldContain "Too many ASN.1 elements"
            source.readByteArray().toHexString() shouldBe hex

            val sibling = "020105".hexToByteArray()
            val nested = Buffer().apply {
                write(byteArrayOf(0x30, (sequence.size + sibling.size).toByte()) + sequence + sibling)
            }
            shouldThrow<SerializationException> {
                DER.decodeFromSource<SourceNested>(nested)
            }.message shouldContain "Too many ASN.1 elements"
            nested.readByteArray().toHexString() shouldBe hex + "020105"
        }
    }
    "OID lookahead leaves discriminator consumption and subtype child limits intact" {
        val serializer = asn1OpenPolymorphicByOidSerializer<OpenByOid>("SourceSurplusOid") {
            subtype<OpenByOidInt>(OpenByOidInt)
        }
        val tree = Asn1Sequence(listOf(OpenByOidInt.oid.encodeToTlv(), Asn1.Int(7), Asn1.Int(8)))
        val source = Buffer().apply { write(tree.derEncoded) }
        shouldThrow<SerializationException> {
            DER.decodeFromSource(serializer, source)
        }.message shouldContain "Too many ASN.1 elements"
        source.readByteArray().toHexString() shouldBe "020108"
    }
    "a serializer cannot consume another root" {
        val source = Buffer().apply { write("020101020102".hexToByteArray()) }
        shouldThrow<SerializationException> {
            DER.decodeFromSource(TwoSourceRootsSerializer, source)
        }.message shouldContain "direct-child limit"
        source.readByteArray().toHexString() shouldBe "020102"
    }
    "source preserves values and rejects surplus, trailing, and malformed boundaries" {
        DER.decodeFromSource<SourceTriple>(Buffer().apply { write(IncrementalFixtures.threeIntegers) }) shouldBe SourceTriple(1, 2, 3)
        listOf(
            IncrementalFixtures.fourIntegers,
            IncrementalFixtures.childBeyondParent,
            IncrementalFixtures.threeIntegers + byteArrayOf(0),
            IncrementalFixtures.threeIntegers + byteArrayOf(2, 1, 4),
            "30090201010201020201".hexToByteArray(),
            "30021f81".hexToByteArray(),
        ).forEach { bytes ->
            shouldThrow<SerializationException> { DER.decodeFromSource<SourceTriple>(Buffer().apply { write(bytes) }) }
        }
    }
    "source rejects unread content from a custom serializer" {
        shouldThrow<SerializationException> {
            DER.decodeFromSource(UnreadSourceSerializer, Buffer().apply { write("3003020101".hexToByteArray()) })
        }
    }
    "a serializer cannot recover after finishing with unread content" {
        val source = Buffer().apply { write("3003020101".hexToByteArray()) }
        shouldThrow<SerializationException> {
            DER.decodeFromSource(RetryAfterUnreadSourceSerializer, source)
        }
        source.readByteArray().toHexString() shouldBe "020101"
    }
    "source validates negative limits even for empty nullable roots" {
        shouldThrow<SerializationException> { DER.decodeFromSource<Int?>(Buffer(), limit = -1) }
        DER.decodeFromSource<Int?>(Buffer(), limit = 0) shouldBe null
    }
    "OID polymorphism rejects SET input before consumption" {
        val serializer = asn1OpenPolymorphicByOidSerializer<OpenByOid>("SourceSetRejected") {
            subtype<OpenByOidInt>(OpenByOidInt)
        }
        val source = Buffer().apply { write("310706022a03020107".hexToByteArray()) }
        shouldThrow<SerializationException> {
            DER.decodeFromSource(serializer, source)
        }.message shouldContain "SET"
        source.readByteArray().toHexString() shouldBe "310706022a03020107"
    }
    "raw OCTET content does not require valid inner ASN.1" {
        DER.decodeFromSource(ByteArraySerializer(), Buffer().apply { write("04033001ff".hexToByteArray()) })
            .toHexString() shouldBe "3001ff"
    }
    "empty OCTET can encapsulate an omitted nullable value" {
        val serializer = OctetStringEncapsulated.serializer(Int.serializer().nullable)
        DER.decodeFromSource(serializer, Buffer().apply { write("0400".hexToByteArray()) }) shouldBe
            OctetStringEncapsulated<Int?>(null)
    }
}
