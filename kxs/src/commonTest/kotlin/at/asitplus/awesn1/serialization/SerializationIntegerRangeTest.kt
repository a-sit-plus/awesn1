package at.asitplus.awesn1.serialization

import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.matrixConfig
import de.infix.testBalloon.framework.core.invocation
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestIntegerRange by matrixSuite {

    "Hardcoded out of bounds" - {

        "Byte decoding rejects ASN.1 INTEGER values outside Byte range" {
            DER.decodeFromByteArray<Byte>("02017f".hexToByteArray()) shouldBe Byte.MAX_VALUE
            DER.decodeFromByteArray<Byte>("020180".hexToByteArray()) shouldBe Byte.MIN_VALUE

            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<Byte>("02020080".hexToByteArray())
            }
            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<Byte>("0202ff7f".hexToByteArray())
            }
        }

        "Short decoding rejects ASN.1 INTEGER values outside Short range" {
            DER.decodeFromByteArray<Short>("02027fff".hexToByteArray()) shouldBe Short.MAX_VALUE
            DER.decodeFromByteArray<Short>("02028000".hexToByteArray()) shouldBe Short.MIN_VALUE

            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<Short>("0203008000".hexToByteArray())
            }
            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<Short>("0203ff7fff".hexToByteArray())
            }
        }

        "UByte decoding rejects ASN.1 INTEGER values outside UByte range" {
            DER.decodeFromByteArray<UByte>("020200ff".hexToByteArray()) shouldBe UByte.MAX_VALUE

            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<UByte>("02020100".hexToByteArray())
            }
        }

        "UShort decoding rejects ASN.1 INTEGER values outside UShort range" {
            DER.decodeFromByteArray<UShort>("020300ffff".hexToByteArray()) shouldBe UShort.MAX_VALUE

            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<UShort>("0203010000".hexToByteArray())
            }
        }

        "UInt decoding accepts unsigned values above signed Int range" {
            DER.decodeFromByteArray<UInt>("02050080000000".hexToByteArray()) shouldBe (Int.MAX_VALUE.toUInt() + 1u)
            DER.decodeFromByteArray<UInt>("020500ffffffff".hexToByteArray()) shouldBe UInt.MAX_VALUE

            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<UInt>("02050100000000".hexToByteArray())
            }
        }

        "ULong decoding accepts unsigned values above signed Long range" {
            DER.decodeFromByteArray<ULong>("0209008000000000000000".hexToByteArray()) shouldBe (Long.MAX_VALUE.toULong() + 1uL)
            DER.decodeFromByteArray<ULong>("020900ffffffffffffffff".hexToByteArray()) shouldBe ULong.MAX_VALUE

            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<ULong>("0209010000000000000000".hexToByteArray())
            }
        }
    }

    data("integer", listOf(
        IntegerRangeFixture(
            name = "Long accepts Long.MAX_VALUE",
            source = Long.MAX_VALUE,
            serializer = Long.serializer(),
            expected = Expected.Value(Long.MAX_VALUE),
        ),
        IntegerRangeFixture(
            name = "Long accepts Long.MIN_VALUE",
            source = Long.MIN_VALUE,
            serializer = Long.serializer(),
            expected = Expected.Value(Long.MIN_VALUE),
        ),
        IntegerRangeFixture(
            name = "Int accepts Int.MAX_VALUE",
            source = Int.MAX_VALUE.toLong(),
            serializer = Int.serializer(),
            expected = Expected.Value(Int.MAX_VALUE),
        ),
        IntegerRangeFixture(
            name = "Int accepts Int.MIN_VALUE",
            source = Int.MIN_VALUE.toLong(),
            serializer = Int.serializer(),
            expected = Expected.Value(Int.MIN_VALUE),
        ),
        IntegerRangeFixture(
            name = "Int rejects Int.MAX_VALUE + 1",
            source = Int.MAX_VALUE.toLong() + 1,
            serializer = Int.serializer(),
            expected = Expected.SerializationFailure,
        ),
        IntegerRangeFixture(
            name = "Int rejects Int.MIN_VALUE - 1",
            source = Int.MIN_VALUE.toLong() - 1,
            serializer = Int.serializer(),
            expected = Expected.SerializationFailure,
        ),
        IntegerRangeFixture(
            name = "UInt accepts UInt.MAX_VALUE",
            source = UInt.MAX_VALUE.toLong(),
            serializer = UInt.serializer(),
            expected = Expected.Value(UInt.MAX_VALUE),
        ),
        IntegerRangeFixture(
            name = "UInt rejects UInt.MAX_VALUE + 1",
            source = UInt.MAX_VALUE.toLong() + 1,
            serializer = UInt.serializer(),
            expected = Expected.SerializationFailure,
        ),
        IntegerRangeFixture(
            name = "Short accepts Short.MAX_VALUE",
            source = Short.MAX_VALUE.toLong(),
            serializer = Short.serializer(),
            expected = Expected.Value(Short.MAX_VALUE),
        ),
        IntegerRangeFixture(
            name = "Short accepts Short.MIN_VALUE",
            source = Short.MIN_VALUE.toLong(),
            serializer = Short.serializer(),
            expected = Expected.Value(Short.MIN_VALUE),
        ),
        IntegerRangeFixture(
            name = "Short rejects Short.MAX_VALUE + 1",
            source = Short.MAX_VALUE.toLong() + 1,
            serializer = Short.serializer(),
            expected = Expected.SerializationFailure,
        ),
        IntegerRangeFixture(
            name = "Short rejects Short.MIN_VALUE - 1",
            source = Short.MIN_VALUE.toLong() - 1,
            serializer = Short.serializer(),
            expected = Expected.SerializationFailure,
        ),
        IntegerRangeFixture(
            name = "UShort accepts UShort.MAX_VALUE",
            source = UShort.MAX_VALUE.toLong(),
            serializer = UShort.serializer(),
            expected = Expected.Value(UShort.MAX_VALUE),
        ),
        IntegerRangeFixture(
            name = "UShort rejects UShort.MAX_VALUE + 1",
            source = UShort.MAX_VALUE.toLong() + 1,
            serializer = UShort.serializer(),
            expected = Expected.SerializationFailure,
        ),
        IntegerRangeFixture(
            name = "Byte accepts Byte.MAX_VALUE",
            source = Byte.MAX_VALUE.toLong(),
            serializer = Byte.serializer(),
            expected = Expected.Value(Byte.MAX_VALUE),
        ),
        IntegerRangeFixture(
            name = "Byte accepts Byte.MIN_VALUE",
            source = Byte.MIN_VALUE.toLong(),
            serializer = Byte.serializer(),
            expected = Expected.Value(Byte.MIN_VALUE),
        ),
        IntegerRangeFixture(
            name = "Byte rejects Byte.MAX_VALUE + 1",
            source = Byte.MAX_VALUE.toLong() + 1,
            serializer = Byte.serializer(),
            expected = Expected.SerializationFailure,
        ),
        IntegerRangeFixture(
            name = "Byte rejects Byte.MIN_VALUE - 1",
            source = Byte.MIN_VALUE.toLong() - 1,
            serializer = Byte.serializer(),
            expected = Expected.SerializationFailure,
        ),
        IntegerRangeFixture(
            name = "UByte accepts UByte.MAX_VALUE",
            source = UByte.MAX_VALUE.toLong(),
            serializer = UByte.serializer(),
            expected = Expected.Value(UByte.MAX_VALUE),
        ),
        IntegerRangeFixture(
            name = "UByte rejects UByte.MAX_VALUE + 1",
            source = UByte.MAX_VALUE.toLong() + 1,
            serializer = UByte.serializer(),
            expected = Expected.SerializationFailure,
        ),
    ), nameFn = { _, it -> it.name }) test { fixture ->
        val encoded = DER.encodeToByteArray(fixture.source)

        when (val expected = fixture.expected) {
            is Expected.Value -> decodeFixture(fixture, encoded) shouldBe expected.value
            Expected.SerializationFailure -> shouldThrow<SerializationException> {
                decodeFixture(fixture, encoded)
            }
        }
    }
}

@Suppress("UNCHECKED_CAST")
private fun decodeFixture(fixture: IntegerRangeFixture, encoded: ByteArray): Any =
    DER.decodeFromByteArray(fixture.serializer as KSerializer<Any>, encoded)

private data class IntegerRangeFixture(
    val name: String,
    val source: Long,
    val serializer: KSerializer<out Any>,
    val expected: Expected,
)

private sealed interface Expected {
    data class Value(val value: Any) : Expected
    data object SerializationFailure : Expected
}
