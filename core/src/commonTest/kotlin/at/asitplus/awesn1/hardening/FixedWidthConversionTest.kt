package at.asitplus.awesn1.at.asitplus.awesn1.hardening

import at.asitplus.awesn1.*
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.withClue
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.shouldBe

/**
 * Guards the hard-capped fixed-width converters ([Asn1Integer.toInt], [Asn1Integer.toLong] and their
 * `…OrNull` variants). These range-check via the magnitude byte length BEFORE running the O(N^2)
 * base-256 -> base-10 decimal conversion, so an oversized (attacker-supplied) magnitude is rejected in
 * O(1) instead of triggering a CPU blow-up.
 */
val FixedWidthConversionTests by matrixSuite {

    "toDouble" {
        Asn1Integer.fromDecimalString("67553994410557445").toDouble() shouldBeIn
                setOf(67553994410557440.0, 67553994410557450.0)
    }

    data(
        "toInt-in-range",
        listOf(
            0 to Asn1Integer(0),
            1 to Asn1Integer(1),
            -1 to Asn1Integer(-1),
            Int.MAX_VALUE to Asn1Integer(Int.MAX_VALUE),
            Int.MIN_VALUE to Asn1Integer(Int.MIN_VALUE),
            127 to Asn1Integer(127),
            -128 to Asn1Integer(-128),
            65536 to Asn1Integer(65536),
        ),
        nameFn = { "toInt=${it.first}" }
    ) test { (expected, value) ->
        value.toInt() shouldBe expected
        value.toIntOrNull() shouldBe expected
    }

    data(
        "toLong-in-range",
        listOf(
            0L to Asn1Integer(0L),
            1L to Asn1Integer(1L),
            -1L to Asn1Integer(-1L),
            Long.MAX_VALUE to Asn1Integer(Long.MAX_VALUE),
            Long.MIN_VALUE to Asn1Integer(Long.MIN_VALUE),
            Int.MAX_VALUE.toLong() + 1 to Asn1Integer(Int.MAX_VALUE.toLong() + 1),
            Int.MIN_VALUE.toLong() - 1 to Asn1Integer(Int.MIN_VALUE.toLong() - 1),
        ),
        nameFn = { "toLong=${it.first}" }
    ) test { (expected, value) ->
        value.toLong() shouldBe expected
        value.toLongOrNull() shouldBe expected
    }

    // Int rejects values that only fit into a Long.
    "toInt rejects Long-only values while toLong accepts them" {
        val tooBigForInt = Asn1Integer(Int.MAX_VALUE.toLong() + 1)
        tooBigForInt.toIntOrNull() shouldBe null
        shouldThrow<NumberFormatException> { tooBigForInt.toInt() }
        tooBigForInt.toLong() shouldBe Int.MAX_VALUE.toLong() + 1

        val tooSmallForInt = Asn1Integer(Int.MIN_VALUE.toLong() - 1)
        tooSmallForInt.toIntOrNull() shouldBe null
        shouldThrow<NumberFormatException> { tooSmallForInt.toInt() }
        tooSmallForInt.toLong() shouldBe Int.MIN_VALUE.toLong() - 1
    }

    // Long rejects values whose magnitude exceeds 8 bytes.
    "toLong rejects values beyond Long range" {
        // Long.MAX_VALUE + 1 == 2^63, magnitude 0x80 00 00 00 00 00 00 00 (8 bytes) but not positive-representable.
        val overflow = Asn1Integer.fromUnsignedByteArray(
            byteArrayOf(0x80.toByte(), 0, 0, 0, 0, 0, 0, 0)
        )
        overflow.toLongOrNull() shouldBe null
        shouldThrow<NumberFormatException> { overflow.toLong() }

        // 9-byte magnitude is out of range for both signs.
        val nineBytes = Asn1Integer.fromUnsignedByteArray(ByteArray(9).also { it[0] = 0x01 })
        nineBytes.toLongOrNull() shouldBe null
        nineBytes.toIntOrNull() shouldBe null
    }

    // A huge magnitude must be rejected quickly; hitting toString() here would take minutes.
    "huge magnitude is rejected in O(1) without stringifying" {
        val hugeMagnitude = ByteArray(64 * 1024).also { it[0] = 0x01 } // 64 KiB, minimal positive
        val huge = Asn1Integer.fromUnsignedByteArray(hugeMagnitude)

        withClue("toIntOrNull must not run the quadratic conversion") {
            huge.toIntOrNull() shouldBe null
        }
        withClue("toLongOrNull must not run the quadratic conversion") {
            huge.toLongOrNull() shouldBe null
        }
        shouldThrow<NumberFormatException> { huge.toInt() }
        shouldThrow<NumberFormatException> { huge.toLong() }

        val hugeNeg = Asn1Integer.fromByteArray(hugeMagnitude, Asn1Integer.Sign.NEGATIVE)
        hugeNeg.toIntOrNull() shouldBe null
        hugeNeg.toLongOrNull() shouldBe null
    }

    // In-range converters agree with the decimal-string representation.
    "converters agree with decimal toString for in-range values" {
        listOf(
            0L, 1L, -1L, 12345L, -98765L,
            Int.MAX_VALUE.toLong(), Int.MIN_VALUE.toLong(), Long.MAX_VALUE, Long.MIN_VALUE
        ).forEach { v ->
            val i = Asn1Integer(v)
            withClue("value=$v") {
                i.toLong() shouldBe v
                i.toDecimalString() shouldBe v.toString()
            }
        }
    }
}
