package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1Real
import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.Asn1Time
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.TagClass
import at.asitplus.awesn1.encoding.parse
import at.asitplus.testballoon.checkAll
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.TestSuiteScope
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.double
import io.kotest.property.arbitrary.filter
import io.kotest.property.arbitrary.float
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.long
import io.kotest.property.arbitrary.map
import io.kotest.property.arbitrary.numericDouble
import io.kotest.property.arbitrary.numericFloat
import io.kotest.property.arbitrary.arbitrary
import io.kotest.property.arbitrary.short
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.descriptors.ClassSerialDescriptorBuilder
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.serializer
import kotlin.time.Instant

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestImplicitTaggingProperty by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "Randomized implicit tagging across default ASN.1-serializable types" - {
        "Boolean" - {
            verifyImplicitTagging(
                valueArb = arbitrary { it.random.nextBoolean() },
            )
        }

        "Byte" - {
            verifyImplicitTagging(
                valueArb = Arb.byte(),
            )
        }

        "Short" - {
            verifyImplicitTagging(
                valueArb = Arb.short(),
            )
        }

        "Int" - {
            verifyImplicitTagging(
                valueArb = Arb.int(),
            )
        }

        "Long" - {
            verifyImplicitTagging(
                valueArb = Arb.long(),
            )
        }

        "Float" - {
            verifyImplicitTagging(
                valueArb = Arb.numericFloat().filter { it != -0.0f },
            )
        }

        "Double" - {
            verifyImplicitTagging(
                valueArb = Arb.numericDouble().filter { it != -0.0 },
            )
        }

        "Char" - {
            verifyImplicitTagging(
                valueArb = asciiCharArb(),
            )
        }

        "String" - {
            verifyImplicitTagging(
                valueArb = asciiStringArb(),
            )
        }

        "ByteArray" - {
            verifyImplicitTagging(
                valueArb = Arb.byteArray(Arb.int(0..48), Arb.byte()),
                assertDecoded = { expected, actual -> actual.toList() shouldBe expected.toList() },
            )
        }

        "kotlin.time.Instant" - {
            verifyImplicitTagging(
                valueArb = instantArb(),
            )
        }

        "ObjectIdentifier" - {
            verifyImplicitTagging(
                valueArb = objectIdentifierArb(),
            )
        }

        "Asn1Integer" - {
            verifyImplicitTagging(
                valueArb = Arb.long().map(::Asn1Integer),
            )
        }

        "Asn1Real" - {
            verifyImplicitTagging(
                valueArb = asn1RealArb(),
            )
        }

        "Asn1Time" - {
            verifyImplicitTagging(
                valueArb = arbitrary { Asn1Time(generateInstant(it.random)) },
            )
        }

        "Asn1BitString" - {
            verifyImplicitTagging(
                valueArb = arbitrary { Asn1BitString(generateByteArray(it.random)) },
            )
        }

        "Asn1String.UTF8" - {
            verifyImplicitTagging(
                valueArb = arbitrary { Asn1String.UTF8(generateAsciiString(it.random)) },
            )
        }

        "Asn1String.IA5" - {
            verifyImplicitTagging(
                valueArb = arbitrary { Asn1String.IA5(generateAsciiString(it.random)) },
            )
        }

        "Asn1String.Visible" - {
            verifyImplicitTagging(
                valueArb = arbitrary { Asn1String.Visible(generateVisibleString(it.random)) },
            )
        }

        "Asn1String.Printable" - {
            verifyImplicitTagging(
                valueArb = arbitrary { Asn1String.Printable(generatePrintableString(it.random)) },
            )
        }

        "Asn1String.Numeric" - {
            verifyImplicitTagging(
                valueArb = arbitrary { Asn1String.Numeric(generateNumericString(it.random)) },
            )
        }

        "Generic Asn1String rejects implicit tagging" {
            val serializer = SingleFieldBoxSerializer(
                valueSerializer = Asn1String.serializer(),
                tagNumber = 7u,
            )
            val raw = Asn1String.UTF8("foo")
            val taggedBytes = DER.encodeToByteArray(ValueClassImplicitlyTaggedGenericAsn1String("foo"))

            shouldThrow<SerializationException> {
                DER.encodeToByteArray(serializer, TaggedValue(raw))
            }
            shouldThrow<SerializationException> {
                DER.decodeFromByteArray(serializer, taggedBytes)
            }
        }

        "Raw Asn1Element rejects implicit tagging" {
            val serializer = SingleFieldBoxSerializer(
                valueSerializer = Asn1Element.serializer(),
                tagNumber = 7u,
            )
            val raw = Asn1Integer(42).encodeToTlv()

            shouldThrow<SerializationException> {
                DER.encodeToByteArray(serializer, TaggedValue(raw))
            }
        }
    }
}

private const val TAG_ITERATIONS = 25
private const val VALUES_PER_TAG = 20

private inline fun <reified T> TestSuiteScope.verifyImplicitTagging(
    valueArb: Arb<T>,
    iterationsPerTag: Int = VALUES_PER_TAG,
    crossinline assertDecoded: (expected: T, actual: T) -> Unit = { expected, actual -> actual shouldBe expected },
) {
    val plainSerializer = SingleFieldBoxSerializer(serializer<T>())

    checkAll(iterations = TAG_ITERATIONS, implicitTagNumberArb()) - { tagNumber ->
        val taggedSerializer = SingleFieldBoxSerializer(serializer<T>(), tagNumber)

        checkAll(iterations = iterationsPerTag, valueArb) { value ->
            val plainChild = encodeSingleChild(plainSerializer, TaggedValue(value))
            val taggedBytes = DER.encodeToByteArray(taggedSerializer, TaggedValue(value))
            val taggedChild = Asn1Element.parse(taggedBytes).asSequence().children.single()
            val decoded = DER.decodeFromByteArray(taggedSerializer, taggedBytes).value

            withClue("tag=$tagNumber value=$value") {
                taggedChild.tag.tagClass shouldBe TagClass.CONTEXT_SPECIFIC
                taggedChild.tag.tagValue shouldBe tagNumber
                taggedChild.withImplicitTag(plainChild.tag).derEncoded.toList() shouldBe plainChild.derEncoded.toList()
                assertDecoded(value, decoded)
            }
        }
    }
}

private fun <T> encodeSingleChild(
    serializer: KSerializer<TaggedValue<T>>,
    value: TaggedValue<T>,
): Asn1Element = Asn1Element.parse(DER.encodeToByteArray(serializer, value)).asSequence().children.single()

private data class TaggedValue<T>(val value: T)

private class SingleFieldBoxSerializer<T>(
    private val valueSerializer: KSerializer<T>,
    tagNumber: ULong? = null,
) : KSerializer<TaggedValue<T>> {
    private val tagAnnotation = tagNumber?.let {
        Asn1Tag(
            tagNumber = it,
            tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
            constructed = Asn1ConstructedBit.INFER,
        )
    }

    override val descriptor: SerialDescriptor = buildClassSerialDescriptor(
        serialName = "TaggedValue<${valueSerializer.descriptor.serialName}>${tagNumber?.let { "[$it]" } ?: ""}",
    ) {
        taggedElement("value", valueSerializer, tagAnnotation)
    }

    override fun serialize(encoder: Encoder, value: TaggedValue<T>) {
        val composite = encoder.beginStructure(descriptor)
        composite.encodeSerializableElement(descriptor, 0, valueSerializer, value.value)
        composite.endStructure(descriptor)
    }

    override fun deserialize(decoder: Decoder): TaggedValue<T> {
        val composite = decoder.beginStructure(descriptor)
        var decoded: T? = null
        while (true) {
            when (val index = composite.decodeElementIndex(descriptor)) {
                0 -> decoded = composite.decodeSerializableElement(descriptor, 0, valueSerializer)
                CompositeDecoder.DECODE_DONE -> {
                    composite.endStructure(descriptor)
                    return TaggedValue(decoded ?: throw SerializationException("Missing tagged value"))
                }

                else -> throw SerializationException("Unexpected index $index for ${descriptor.serialName}")
            }
        }
    }
}

private fun ClassSerialDescriptorBuilder.taggedElement(
    name: String,
    serializer: KSerializer<*>,
    tagAnnotation: Asn1Tag?,
) {
    element(
        elementName = name,
        descriptor = serializer.descriptor,
        annotations = tagAnnotation?.let(::listOf) ?: emptyList(),
    )
}

private fun implicitTagNumberArb(): Arb<ULong> = arbitrary { rs ->
    generateImplicitTagNumber(rs.random)
}

private fun asciiCharArb(): Arb<Char> = arbitrary { rs ->
    VISIBLE_ASCII[rs.random.nextInt(VISIBLE_ASCII.length)]
}

private fun asciiStringArb(maxLength: Int = 32): Arb<String> = arbitrary { rs ->
    buildRandomString(rs.random.nextInt(maxLength + 1), VISIBLE_ASCII, rs.random)
}

private fun visibleStringArb(maxLength: Int = 32): Arb<String> = arbitrary { rs ->
    buildRandomString(rs.random.nextInt(maxLength + 1), VISIBLE_ASCII, rs.random)
}

private fun printableStringArb(maxLength: Int = 32): Arb<String> = arbitrary { rs ->
    buildRandomString(rs.random.nextInt(maxLength + 1), PRINTABLE_ASCII, rs.random)
}

private fun numericStringArb(maxLength: Int = 32): Arb<String> = arbitrary { rs ->
    buildRandomString(rs.random.nextInt(maxLength + 1), NUMERIC_ASCII, rs.random)
}

private fun instantArb(): Arb<Instant> = arbitrary { rs ->
    generateInstant(rs.random)
}

private fun objectIdentifierArb(): Arb<ObjectIdentifier> = arbitrary { rs ->
    val first = rs.random.nextInt(0, 3)
    val second = rs.random.nextInt(0, if (first < 2) 40 else 48)
    val tailCount = rs.random.nextInt(0, 10)
    val nodes = buildList {
        add(first)
        add(second)
        repeat(tailCount) {
            add(generateOidArc(rs.random))
        }
    }
    ObjectIdentifier(nodes.joinToString("."))
}

private fun asn1RealArb(): Arb<Asn1Real> = arbitrary { rs ->
    when (rs.random.nextInt(10)) {
        0 -> Asn1Real.Zero
        1 -> Asn1Real.PositiveInfinity
        2 -> Asn1Real.NegativeInfinity
        3 -> Asn1Real(Arb.numericFloat().filter { it != -0.0f }.bind())
        else -> Asn1Real(Arb.numericDouble().filter { it != -0.0 }.bind())
    }
}

private fun generateByteArray(
    random: kotlin.random.Random,
    maxLength: Int = 48,
): ByteArray = ByteArray(random.nextInt(maxLength + 1)) { random.nextInt(0, 256).toByte() }

private fun generateInstant(random: kotlin.random.Random): Instant =
    Instant.fromEpochSeconds(random.nextLong(MIN_EPOCH_SECONDS, MAX_EPOCH_SECONDS))

private fun generateAsciiString(random: kotlin.random.Random, maxLength: Int = 32): String =
    buildRandomString(random.nextInt(maxLength + 1), VISIBLE_ASCII, random)

private fun generateVisibleString(random: kotlin.random.Random, maxLength: Int = 32): String =
    buildRandomString(random.nextInt(maxLength + 1), VISIBLE_ASCII, random)

private fun generatePrintableString(random: kotlin.random.Random, maxLength: Int = 32): String =
    buildRandomString(random.nextInt(maxLength + 1), PRINTABLE_ASCII, random)

private fun generateNumericString(random: kotlin.random.Random, maxLength: Int = 32): String =
    buildRandomString(random.nextInt(maxLength + 1), NUMERIC_ASCII, random)

private fun generateOidArc(random: kotlin.random.Random): Int = when (random.nextInt(10)) {
    0 -> 0
    1 -> 1
    2 -> 127
    3 -> 128
    4 -> 16_383
    5 -> 16_384
    6 -> 2_097_151
    7 -> 2_097_152
    else -> random.nextInt(0, Int.MAX_VALUE)
}

private fun generateImplicitTagNumber(random: kotlin.random.Random): ULong = when (random.nextInt(20)) {
    0 -> 0u
    1 -> 1u
    2 -> 2u
    3 -> 15u
    4 -> 16u
    5 -> 29u
    6 -> 30u
    7 -> 31u
    8 -> 32u
    9 -> 63u
    10 -> 64u
    11 -> 127u
    12 -> 128u
    13 -> 255u
    14 -> 256u
    15 -> 16_383u
    16 -> 16_384u
    17 -> 65_535u
    18 -> 65_536u
    else -> when (random.nextInt(4)) {
        0 -> random.nextInt(0, 32).toULong()
        1 -> random.nextInt(32, 256).toULong()
        2 -> random.nextInt(256, 16_385).toULong()
        else -> random.nextInt(16_385, 1_000_000).toULong()
    }
}

private fun buildRandomString(
    length: Int,
    alphabet: String,
    random: kotlin.random.Random,
): String = buildString(length) {
    repeat(length) {
        append(alphabet[random.nextInt(alphabet.length)])
    }
}

private const val MIN_EPOCH_SECONDS = -2_208_988_800L
private const val MAX_EPOCH_SECONDS = 4_102_444_800L
private const val VISIBLE_ASCII = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
private const val PRINTABLE_ASCII = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?"
private const val NUMERIC_ASCII = "0123456789 "
