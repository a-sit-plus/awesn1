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
import at.asitplus.awesn1.serialization.OctetStringEncapsulated
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import kotlinx.serialization.*
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.nullable
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*

@Serializable
private data class SourceTriple(val a: Int, val b: Int, val c: Int)

@Serializable
private data class SourceNested(val value: SourceTriple, val sibling: Int)

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
