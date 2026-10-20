@file:OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)

package at.asitplus.awesn1.serialization.api

import at.asitplus.awesn1.hardening.IncrementalFixtures
import at.asitplus.awesn1.io.decodeFromSource
import at.asitplus.awesn1.serialization.DER
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.io.Buffer
import kotlinx.serialization.*
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*

@Serializable
private data class SourceTriple(val a: Int, val b: Int, val c: Int)

private object UnreadSourceSerializer : KSerializer<Unit> {
    override val descriptor = buildClassSerialDescriptor("UnreadSource") { element<Int>("a") }
    override fun serialize(encoder: Encoder, value: Unit) = error("decode only")
    override fun deserialize(decoder: Decoder) {
        decoder.beginStructure(descriptor).endStructure(descriptor)
    }
}

val IncrementalSourceTest by matrixSuite {
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
    "source validates negative limits even for empty nullable roots" {
        shouldThrow<SerializationException> { DER.decodeFromSource<Int?>(Buffer(), limit = -1) }
        DER.decodeFromSource<Int?>(Buffer(), limit = 0) shouldBe null
    }
    "raw OCTET content does not require valid inner ASN.1" {
        DER.decodeFromSource(ByteArraySerializer(), Buffer().apply { write("04033001ff".hexToByteArray()) })
            .toHexString() shouldBe "3001ff"
    }
}
