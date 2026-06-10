package at.asitplus.awesn1.at.asitplus.awesn1.hardening

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.encoding.*
import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.matrixConfig
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

private fun primitive(hex: String): Asn1Primitive =
    Asn1Element.parseFromDerHexString(hex)
        .shouldBeInstanceOf<Asn1Primitive>()

data class SignedIntegerFixture(
    val der: String,
    val expected: Long,
)

data class UnsignedIntegerFixture(
    val der: String,
    val expected: ULong,
)

val asn1IntegerSemanticParsing by matrixSuite {

    data(
        "valid minimal signed INTEGERs",
        listOf(
            SignedIntegerFixture("020100", 0L),
            SignedIntegerFixture("020101", 1L),
            SignedIntegerFixture("02017f", 127L),
            SignedIntegerFixture("02020080", 128L),
            SignedIntegerFixture("020200ff", 255L),
            SignedIntegerFixture("02020100", 256L),

            SignedIntegerFixture("0201ff", -1L),
            SignedIntegerFixture("020180", -128L),
            SignedIntegerFixture("0202ff7f", -129L),
            SignedIntegerFixture("0202ff00", -256L),
        ),
        nameFn = { index, fixture -> "$index: ${fixture.der}" },
    ) test { fixture ->
        val p = primitive(fixture.der)

        p.decodeToAsn1Integer().toString().toLong() shouldBe fixture.expected
        p.decodeToLong() shouldBe fixture.expected

        if (fixture.expected in Int.MIN_VALUE..Int.MAX_VALUE) {
            p.decodeToInt() shouldBe fixture.expected.toInt()
        }
    }

    data(
        "non-minimal positive INTEGER encodings",
        listOf(
            "02020000",     // 0 encoded as 00 00
            "02020001",     // 1 encoded as 00 01
            "0202007f",     // 127 encoded as 00 7f
            "0203000080",   // 128 encoded as 00 00 80
            "0203000100",   // 256 encoded as 00 01 00
        ),
        nameFn = { index, der -> "$index: $der" },
    ) - { der ->
        val p = primitive(der)

        data("lenient", listOf(true, false)) test { lenient ->
            if (lenient) {
                p.decodeToAsn1Integer(lenient = true).toString() shouldBe der.substring(4).toInt(radix = 16).toString()
                p.decodeToLong(lenient = true).toString() shouldBe der.substring(4).toInt(radix = 16).toString()
                p.decodeToInt(lenient = true).toString() shouldBe der.substring(4).toInt(radix = 16).toString()
                p.decodeToULong(lenient = true).toString() shouldBe der.substring(4).toInt(radix = 16).toString()
                p.decodeToUInt(lenient = true).toString() shouldBe der.substring(4).toInt(radix = 16).toString()
            } else {
                shouldThrow<Asn1Exception> { p.decodeToAsn1Integer() }
                shouldThrow<Asn1Exception> { p.decodeToLong() }
                shouldThrow<Asn1Exception> { p.decodeToInt() }
                shouldThrow<Asn1Exception> { p.decodeToULong() }
                shouldThrow<Asn1Exception> { p.decodeToUInt() }
            }
        }
    }

    data(
        "non-minimal negative INTEGER encodings",
        listOf(
            "0202ffff",     // -1 encoded as ff ff
            "0202ff80",     // -128 encoded as ff 80
            "0203ffff7f",   // -129 encoded as ff ff 7f
            "0203ffff00",   // -256 encoded as ff ff 00
        ),
        nameFn = { index, der -> "$index: $der" },
    ) test { der ->
        val p = primitive(der)

        shouldThrow<Asn1Exception> { p.decodeToAsn1Integer() }
        shouldThrow<Asn1Exception> { p.decodeToLong() }
        shouldThrow<Asn1Exception> { p.decodeToInt() }
        shouldThrow<Asn1Exception> { p.decodeToULong() }
        shouldThrow<Asn1Exception> { p.decodeToUInt() }
    }

    data(
        "empty INTEGER content",
        listOf("0200"),
        nameFn = { index, der -> "$index: $der" },
    ) test { der ->
        val p = primitive(der)

        shouldThrow<Asn1Exception> { p.decodeToAsn1Integer() }
        shouldThrow<Asn1Exception> { p.decodeToLong() }
        shouldThrow<Asn1Exception> { p.decodeToInt() }
        shouldThrow<Asn1Exception> { p.decodeToULong() }
        shouldThrow<Asn1Exception> { p.decodeToUInt() }
    }

    data(
        "negative INTEGER encodings rejected by unsigned decoders",
        listOf(
            "0201ff",     // -1
            "020180",     // -128
            "0202ff7f",   // -129
            "0202ff00",   // -256
        ),
        nameFn = { index, der -> "$index: $der" },
    ) test { der ->
        val p = primitive(der)

        shouldThrow<Asn1Exception> { p.decodeToULong() }
        shouldThrow<Asn1Exception> { p.decodeToUInt() }
    }

    data(
        "valid non-negative INTEGERs for unsigned decoders",
        listOf(
            UnsignedIntegerFixture("020100", 0uL),
            UnsignedIntegerFixture("020101", 1uL),
            UnsignedIntegerFixture("02017f", 127uL),
            UnsignedIntegerFixture("02020080", 128uL),
            UnsignedIntegerFixture("020200ff", 255uL),
            UnsignedIntegerFixture("02020100", 256uL),
            UnsignedIntegerFixture("02087fffffffffffffff", Long.MAX_VALUE.toULong()),
            UnsignedIntegerFixture("0209008000000000000000", 9223372036854775808uL),
            UnsignedIntegerFixture("020900ffffffffffffffff", ULong.MAX_VALUE),
        ),
        nameFn = { index, fixture -> "$index: ${fixture.der}" },
    ) test { fixture ->
        val p = primitive(fixture.der)

        p.decodeToULong() shouldBe fixture.expected

        if (fixture.expected <= UInt.MAX_VALUE) {
            p.decodeToUInt() shouldBe fixture.expected.toUInt()
        }
    }

    data(
        "signed range overflow",
        listOf(
            // Int.MAX_VALUE     =  2147483647 = 0x7fffffff
            // Int.MAX_VALUE + 1 =  2147483648 = 0x80000000
            "02050080000000" to "int-positive-overflow",

            // Int.MIN_VALUE     = -2147483648 = 0x80000000
            // Int.MIN_VALUE - 1 = -2147483649 = 0xff7fffffff
            "0205ff7fffffff" to "int-negative-overflow",

            // Long.MAX_VALUE     =  9223372036854775807 = 0x7fffffffffffffff
            // Long.MAX_VALUE + 1 =  9223372036854775808 = 0x8000000000000000
            "0209008000000000000000" to "long-positive-overflow",

            // Long.MIN_VALUE     = -9223372036854775808 = 0x8000000000000000
            // Long.MIN_VALUE - 1 = -9223372036854775809 = 0xff7fffffffffffffff
            "0209ff7fffffffffffffff" to "long-negative-overflow",
        ),
        nameFn = { index, fixture -> "$index: ${fixture.first} -> ${fixture.second}" },
    ) test { (der, decoder) ->
        val p = primitive(der)

        when (decoder) {
            "int-positive-overflow",
            "int-negative-overflow" ->
                shouldThrow<Asn1Exception> { p.decodeToInt() }.message shouldBe "Input with size 5 is out of bounds for Int"

            "long-positive-overflow",
            "long-negative-overflow" ->
                shouldThrow<Asn1Exception> { p.decodeToLong() }.message shouldBe "Input with size 9 is out of bounds for Long"

            else -> error("Unknown decoder case: $decoder")
        }
    }

    data(
        "signed range boundaries",
        listOf(
            // Int.MAX_VALUE
            SignedIntegerFixture("02047fffffff", Int.MAX_VALUE.toLong()),

            // Int.MIN_VALUE
            SignedIntegerFixture("020480000000", Int.MIN_VALUE.toLong()),

            // Long.MAX_VALUE
            SignedIntegerFixture("02087fffffffffffffff", Long.MAX_VALUE),

            // Long.MIN_VALUE
            SignedIntegerFixture("02088000000000000000", Long.MIN_VALUE),
        ),
        nameFn = { index, fixture -> "$index: ${fixture.der}" },
    ) test { fixture ->
        val p = primitive(fixture.der)

        p.decodeToLong() shouldBe fixture.expected

        if (fixture.expected in Int.MIN_VALUE..Int.MAX_VALUE) {
            p.decodeToInt() shouldBe fixture.expected.toInt()
        }
    }

    data(
        "unsigned UInt range overflow",
        listOf(
            "02050100000000",         // UInt.MAX_VALUE + 1
            "020900ffffffffffffffff", // ULong.MAX_VALUE
        ),
        nameFn = { index, der -> "$index: $der" },
    ) test { der ->
        val p = primitive(der)

        shouldThrow<Asn1Exception> {
            p.decodeToUInt()
        }
    }

    data(
        "raw parser accepts TLV but semantic INTEGER decoder rejects content",
        listOf(
            "02020001" to byteArrayOf(0x00, 0x01),
            "0202ffff" to byteArrayOf(0xff.toByte(), 0xff.toByte()),
        ),
        nameFn = { index, fixture -> "$index: ${fixture.first}" },
    ) test { (der, expectedContent) ->
        val p = primitive(der)

        p.tag shouldBe Asn1Element.Tag.INT
        p.content.contentEquals(expectedContent) shouldBe true

        shouldThrow<Asn1Exception> {
            p.decodeToAsn1Integer()
        }

        shouldThrow<Asn1Exception> {
            p.decodeToInt()
        }
    }
}