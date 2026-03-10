package at.asitplus.awesn1.serialization

import at.asitplus.testballoon.checkAll
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.TestSuiteScope
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.arbitrary
import io.kotest.property.arbitrary.bind
import io.kotest.property.arbitrary.boolean
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.filter
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.list
import io.kotest.property.arbitrary.long
import io.kotest.property.arbitrary.map
import io.kotest.property.arbitrary.map
import io.kotest.property.arbitrary.numericDouble
import io.kotest.property.arbitrary.numericFloat
import io.kotest.property.arbitrary.set
import io.kotest.property.arbitrary.string
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlin.jvm.JvmInline

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestRoundTripContracts by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "Round-trip contracts for generics, collections, maps, and value classes" - {
        "Generic box of primitive value" - {
            assertRoundTrip(primitiveBoxArb())
        }

        "Generic box of list payload" - {
            assertRoundTrip(genericListBoxArb())
        }

        "Generic pair envelope with mixed payloads" - {
            assertRoundTrip(mixedPairEnvelopeArb())
        }

        "Nested collections" - {
            assertRoundTrip(nestedCollectionsArb())
        }

        "Map with structured values" - {
            assertRoundTrip(structuredMapEnvelopeArb())
        }

        "Value classes inside ordinary models" - {
            assertRoundTrip(valueClassEnvelopeArb())
        }

        "Generic envelope of structured payload" - {
            assertRoundTrip(genericStructuredEnvelopeArb())
        }

        "Byte arrays inside collections" - {
            assertRoundTrip(
                arb = byteArrayEnvelopeArb(),
                assertDecoded = ::assertByteArrayEnvelopeEquals,
            )
        }

        "Implicit tagging on generic and collection-bearing model" - {
            assertRoundTrip(taggedImplicitEnvelopeArb())
        }

        "Explicitly tagged wrapper around structured payload" - {
            assertRoundTrip(explicitEnvelopeArb())
        }

        "Octet string encapsulation around structured payload" - {
            assertRoundTrip(octetWrappedEnvelopeArb())
        }

        "Bit string byte arrays with tagging" - {
            assertRoundTrip(
                arb = bitStringEnvelopeArb(),
                assertDecoded = ::assertBitStringEnvelopeEquals,
            )
        }
    }
}

private const val ROUND_TRIP_ITERATIONS = 75

private inline fun <reified T> TestSuiteScope.assertRoundTrip(
    arb: Arb<T>,
    iterations: Int = ROUND_TRIP_ITERATIONS,
    crossinline assertDecoded: (expected: T, actual: T) -> Unit = { expected, actual -> actual shouldBe expected },
) {
    checkAll(iterations = iterations, arb) { value ->
        assertDecoded(value, DER.decodeFromByteArray<T>(DER.encodeToByteArray(value)))
    }
}

private fun primitiveBoxArb(): Arb<GenericBox<Long>> =
    Arb.long().map(::GenericBox)

private fun genericListBoxArb(): Arb<GenericBox<List<Int>>> =
    Arb.list(Arb.int(), 0..8).map(::GenericBox)

private fun mixedPairEnvelopeArb(): Arb<PairEnvelope<Int, String>> =
    Arb.bind(
        Arb.int(),
        printableAsciiArb(),
    ) { left, right ->
        PairEnvelope(left = left, right = right)
    }

private fun nestedCollectionsArb(): Arb<NestedCollectionsEnvelope> =
    Arb.bind(
        Arb.list(printableAsciiArb(), 0..6),
        Arb.set(Arb.int(-16..16), 0..6),
        Arb.list(Arb.list(Arb.int(-32..32), 0..5), 0..5),
        Arb.list(Arb.boolean(), 0..12),
    ) { names, flags, matrix, toggles ->
        NestedCollectionsEnvelope(
            names = names,
            flags = flags,
            matrix = matrix,
            toggles = toggles,
        )
    }

private fun structuredMapEnvelopeArb(): Arb<StructuredMapEnvelope> =
    Arb.bind(
        printableAsciiArb(),
        Arb.map(Arb.int(-12..12), smallRecordArb(), 0, 6),
        Arb.list(Arb.int(-8..8), 0..6),
    ) { label, values, trailer ->
        StructuredMapEnvelope(
            label = label,
            values = values,
            trailer = trailer,
        )
    }

private fun valueClassEnvelopeArb(): Arb<ValueClassEnvelope> =
    Arb.bind(
        Arb.int(),
        printableAsciiArb(),
        Arb.list(Arb.int(-32..32), 0..8),
        Arb.list(printableAsciiArb(), 0..6),
        Arb.map(printableAsciiKeyArb(), Arb.int(-64..64), 0, 6),
    ) { id, label, scores, aliases, metadata ->
        ValueClassEnvelope(
            id = InlineInt(id),
            label = InlineString(label),
            scores = scores.map(::InlineInt),
            aliases = aliases.map(::InlineString),
            metadata = metadata.mapKeys { InlineString(it.key) }.mapValues { InlineInt(it.value) },
        )
    }

private fun genericStructuredEnvelopeArb(): Arb<GenericEnvelope<SmallRecord>> =
    Arb.bind(
        printableAsciiArb(),
        smallRecordArb(),
        Arb.list(smallRecordArb(), 0..5),
    ) { name, payload, history ->
        GenericEnvelope(
            name = name,
            payload = payload,
            history = history,
        )
    }

private fun byteArrayEnvelopeArb(): Arb<ByteArrayEnvelope> =
    Arb.bind(
        Arb.list(Arb.byteArray(Arb.int(0..24), Arb.byte()), 0..6),
        Arb.map(printableAsciiKeyArb(), Arb.byteArray(Arb.int(0..16), Arb.byte()), 0, 5),
    ) { values, named ->
        ByteArrayEnvelope(
            values = values.map {it.copyOf()},
            named = named.mapValues { (_, value) -> value.copyOf() },
        )
    }

private fun taggedImplicitEnvelopeArb(): Arb<TaggedImplicitEnvelope> =
    Arb.bind(
        Arb.int(-1024..1024),
        printableAsciiArb(),
        Arb.list(Arb.int(-32..32), 0..6),
        Arb.map(printableAsciiKeyArb(), printableAsciiArb(), 0, 5),
    ) { id, label, numbers, aliases ->
        TaggedImplicitEnvelope(
            id = id,
            label = label,
            numbers = numbers,
            aliases = aliases,
        )
    }

private fun explicitEnvelopeArb(): Arb<ExplicitEnvelope> =
    Arb.bind(
        printableAsciiArb(),
        smallRecordArb(),
        Arb.list(Arb.int(-12..12), 0..6),
    ) { marker, payload, trail ->
        ExplicitEnvelope(
            marker = marker,
            wrapped = ExplicitlyTagged(payload),
            trail = trail,
        )
    }

private fun octetWrappedEnvelopeArb(): Arb<OctetWrappedEnvelope> =
    Arb.bind(
        Arb.int(-16..16),
        smallRecordArb(),
        printableAsciiArb(),
    ) { version, payload, note ->
        OctetWrappedEnvelope(
            version = version,
            wrapped = OctetStringEncapsulated(payload),
            note = note,
        )
    }

private fun bitStringEnvelopeArb(): Arb<BitStringEnvelope> =
    Arb.bind(
        Arb.byteArray(Arb.int(0..24), Arb.byte()),
        Arb.byteArray(Arb.int(0..24), Arb.byte()),
        printableAsciiArb(),
    ) { flags, taggedFlags, note ->
        BitStringEnvelope(
            flags = flags.copyOf(),
            taggedFlags = taggedFlags.copyOf(),
            note = note,
        )
    }

private fun smallRecordArb(): Arb<SmallRecord> =
    Arb.bind(
        Arb.int(-128..128),
        printableAsciiArb(),
        Arb.numericDouble().filter { it != -0.0 && it.isFinite() },
        Arb.numericFloat().filter { it != -0.0f && it.isFinite() },
        Arb.boolean(),
    ) { id, name, ratio, weight, enabled ->
        SmallRecord(
            id = id,
            name = name,
            ratio = ratio,
            weight = weight,
            enabled = enabled,
        )
    }

private fun printableAsciiArb(): Arb<String> = Arb.string(0..24, PRINTABLE_ASCII)

private fun printableAsciiKeyArb(): Arb<String> = Arb.string(1..12, KEY_ASCII)

private fun assertByteArrayEnvelopeEquals(expected: ByteArrayEnvelope, actual: ByteArrayEnvelope) {
    actual.values.map(ByteArray::toList) shouldBe expected.values.map(ByteArray::toList)
    actual.named.mapValues { (_, value) -> value.toList() } shouldBe expected.named.mapValues { (_, value) -> value.toList() }
}

private fun assertBitStringEnvelopeEquals(expected: BitStringEnvelope, actual: BitStringEnvelope) {
    actual.flags.toList() shouldBe expected.flags.toList()
    actual.taggedFlags.toList() shouldBe expected.taggedFlags.toList()
    actual.note shouldBe expected.note
}

@Serializable
private data class GenericBox<T>(
    val value: T,
)

@Serializable
private data class PairEnvelope<A, B>(
    val left: A,
    val right: B,
)

@Serializable
private data class GenericEnvelope<T>(
    val name: String,
    val payload: T,
    val history: List<T>,
)

@Serializable
private data class NestedCollectionsEnvelope(
    val names: List<String>,
    val flags: Set<Int>,
    val matrix: List<List<Int>>,
    val toggles: List<Boolean>,
)

@Serializable
private data class StructuredMapEnvelope(
    val label: String,
    val values: Map<Int, SmallRecord>,
    val trailer: List<Int>,
)

@Serializable
private data class ValueClassEnvelope(
    val id: InlineInt,
    val label: InlineString,
    val scores: List<InlineInt>,
    val aliases: List<InlineString>,
    val metadata: Map<InlineString, InlineInt>,
)

@Serializable
private data class ByteArrayEnvelope(
    val values: List<ByteArray>,
    val named: Map<String, ByteArray>,
)

@Serializable
@Asn1Tag(tagNumber = 150u, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
private data class TaggedImplicitEnvelope(
    @Asn1Tag(tagNumber = 0u, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val id: Int,
    @Asn1Tag(tagNumber = 1u, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val label: String,
    @Asn1Tag(tagNumber = 2u, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val numbers: List<Int>,
    @Asn1Tag(tagNumber = 3u, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val aliases: Map<String, String>,
)

@Serializable
private data class ExplicitEnvelope(
    val marker: String,
    @Asn1Tag(
        tagNumber = 4u,
        tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
        constructed = Asn1ConstructedBit.CONSTRUCTED,
    )
    val wrapped: ExplicitlyTagged<SmallRecord>,
    val trail: List<Int>,
)

@Serializable
private data class OctetWrappedEnvelope(
    val version: Int,
    val wrapped: OctetStringEncapsulated<SmallRecord>,
    val note: String,
)

@Serializable
private data class BitStringEnvelope(
    @Asn1BitString
    val flags: ByteArray,
    @Asn1BitString
    @Asn1Tag(tagNumber = 33u, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val taggedFlags: ByteArray,
    val note: String,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is BitStringEnvelope) return false

        if (!flags.contentEquals(other.flags)) return false
        if (!taggedFlags.contentEquals(other.taggedFlags)) return false
        if (note != other.note) return false

        return true
    }

    override fun hashCode(): Int {
        var result = flags.contentHashCode()
        result = 31 * result + taggedFlags.contentHashCode()
        result = 31 * result + note.hashCode()
        return result
    }
}

@Serializable
private data class SmallRecord(
    val id: Int,
    val name: String,
    val ratio: Double,
    val weight: Float,
    val enabled: Boolean,
)

@Serializable
@JvmInline
private value class InlineInt(val value: Int)

@Serializable
@JvmInline
private value class InlineString(val value: String)

private const val PRINTABLE_ASCII = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?"
private const val KEY_ASCII = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
