package at.asitplus.awesn1.serialization

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
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

    primitiveIntegerSourceCases.asData(name = "source integer", nameFn = { it.name }) test { source ->
        encodeSource(source).toHexString().lowercase() shouldBe source.derHex
    }

    primitiveIntegerCrossCases.asData(name = "integer compatibility", nameFn = { "${it.source.name} -> ${it.target.name}" }) test { case ->
        val encoded = encodeSource(case.source)
        encoded.toHexString().lowercase() shouldBe case.source.derHex

        when (val expected = case.expected()) {
            is Expected.Value -> decodeTarget(case.target, encoded) shouldBe expected.value
            Expected.SerializationFailure -> shouldThrow<SerializationException> {
                decodeTarget(case.target, encoded)
            }
        }
    }

    "Enum decoding rejects ordinals outside Kotlin Int range" {
        DER.decodeFromByteArray<TestEnum>("0a0100".hexToByteArray()) shouldBe TestEnum.ZERO
        DER.decodeFromByteArray<TestEnum>("0a0101".hexToByteArray()) shouldBe TestEnum.ONE

        shouldThrow<SerializationException> {
            DER.decodeFromByteArray<TestEnum>("0a050080000000".hexToByteArray())
        }
        shouldThrow<SerializationException> {
            DER.decodeFromByteArray<TestEnum>("0a01ff".hexToByteArray())
        }
    }
}

private val primitiveIntegerSourceCases = listOf(
    SourceIntegerCase("Byte.MIN_VALUE", "-128", "020180") { DER.encodeToByteArray(Byte.MIN_VALUE) },
    SourceIntegerCase("Byte.MAX_VALUE", "127", "02017f") { DER.encodeToByteArray(Byte.MAX_VALUE) },
    SourceIntegerCase("Short.MIN_VALUE", "-32768", "02028000") { DER.encodeToByteArray(Short.MIN_VALUE) },
    SourceIntegerCase("Short.MAX_VALUE", "32767", "02027fff") { DER.encodeToByteArray(Short.MAX_VALUE) },
    SourceIntegerCase("Int.MIN_VALUE", "-2147483648", "020480000000") { DER.encodeToByteArray(Int.MIN_VALUE) },
    SourceIntegerCase("Int.MAX_VALUE", "2147483647", "02047fffffff") { DER.encodeToByteArray(Int.MAX_VALUE) },
    SourceIntegerCase("Long.MIN_VALUE", "-9223372036854775808", "02088000000000000000") { DER.encodeToByteArray(Long.MIN_VALUE) },
    SourceIntegerCase("Long.MAX_VALUE", "9223372036854775807", "02087fffffffffffffff") { DER.encodeToByteArray(Long.MAX_VALUE) },
    SourceIntegerCase("UByte.MIN_VALUE", "0", "020100") { DER.encodeToByteArray(UByte.MIN_VALUE) },
    SourceIntegerCase("UByte.MAX_VALUE", "255", "020200ff") { DER.encodeToByteArray(UByte.MAX_VALUE) },
    SourceIntegerCase("UShort.MIN_VALUE", "0", "020100") { DER.encodeToByteArray(UShort.MIN_VALUE) },
    SourceIntegerCase("UShort.MAX_VALUE", "65535", "020300ffff") { DER.encodeToByteArray(UShort.MAX_VALUE) },
    SourceIntegerCase("UInt.MIN_VALUE", "0", "020100") { DER.encodeToByteArray(UInt.MIN_VALUE) },
    SourceIntegerCase("UInt.MAX_VALUE", "4294967295", "020500ffffffff") { DER.encodeToByteArray(UInt.MAX_VALUE) },
    SourceIntegerCase("ULong.MIN_VALUE", "0", "020100") { DER.encodeToByteArray(ULong.MIN_VALUE) },
    SourceIntegerCase("ULong.MAX_VALUE", "18446744073709551615", "020900ffffffffffffffff") { DER.encodeToByteArray(ULong.MAX_VALUE) },
)

private val primitiveIntegerTargetCases = listOf(
    TargetIntegerCase("Byte", "-128", "127", String::toByte) { DER.decodeFromByteArray<Byte>(it) },
    TargetIntegerCase("Short", "-32768", "32767", String::toShort) { DER.decodeFromByteArray<Short>(it) },
    TargetIntegerCase("Int", "-2147483648", "2147483647", String::toInt) { DER.decodeFromByteArray<Int>(it) },
    TargetIntegerCase("Long", "-9223372036854775808", "9223372036854775807", String::toLong) { DER.decodeFromByteArray<Long>(it) },
    TargetIntegerCase("UByte", "0", "255", String::toUByte) { DER.decodeFromByteArray<UByte>(it) },
    TargetIntegerCase("UShort", "0", "65535", String::toUShort) { DER.decodeFromByteArray<UShort>(it) },
    TargetIntegerCase("UInt", "0", "4294967295", String::toUInt) { DER.decodeFromByteArray<UInt>(it) },
    TargetIntegerCase("ULong", "0", "18446744073709551615", String::toULong) { DER.decodeFromByteArray<ULong>(it) },
)

private val primitiveIntegerCrossCases =
    primitiveIntegerSourceCases.flatMap { source -> primitiveIntegerTargetCases.map { target -> CrossIntegerCase(source, target) } }

private fun encodeSource(source: SourceIntegerCase): ByteArray =
    source.encode()

private fun decodeTarget(target: TargetIntegerCase, encoded: ByteArray): Any =
    target.decode(encoded)

private data class SourceIntegerCase(
    val name: String,
    val decimalValue: String,
    val derHex: String,
    val encode: () -> ByteArray,
)

private data class TargetIntegerCase(
    val name: String,
    val minDecimalValue: String,
    val maxDecimalValue: String,
    val parse: (String) -> Any,
    val decode: (ByteArray) -> Any,
)

private data class CrossIntegerCase(
    val source: SourceIntegerCase,
    val target: TargetIntegerCase,
) {
    fun expected(): Expected {
        val value = DecimalInteger.parse(source.decimalValue)
        val min = DecimalInteger.parse(target.minDecimalValue)
        val max = DecimalInteger.parse(target.maxDecimalValue)
        return if (value in min..max) Expected.Value(target.parse(source.decimalValue))
        else Expected.SerializationFailure
    }
}

private data class DecimalInteger(
    val negative: Boolean,
    val magnitude: String,
) : Comparable<DecimalInteger> {
    override fun compareTo(other: DecimalInteger): Int = when {
        negative != other.negative -> if (negative) -1 else 1
        negative -> compareMagnitude(other) * -1
        else -> compareMagnitude(other)
    }

    private fun compareMagnitude(other: DecimalInteger): Int = when {
        magnitude.length != other.magnitude.length -> magnitude.length.compareTo(other.magnitude.length)
        else -> magnitude.compareTo(other.magnitude)
    }

    companion object {
        fun parse(input: String): DecimalInteger {
            val negative = input.startsWith('-')
            val digits = input.removePrefix("-").trimStart('0').ifEmpty { "0" }
            return DecimalInteger(negative = negative && digits != "0", magnitude = digits)
        }
    }
}

private sealed interface Expected {
    data class Value(val value: Any) : Expected
    data object SerializationFailure : Expected
}

@Serializable
private enum class TestEnum {
    ZERO,
    ONE,
}
