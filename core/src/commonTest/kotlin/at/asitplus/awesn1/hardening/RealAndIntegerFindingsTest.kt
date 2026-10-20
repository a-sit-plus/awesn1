// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(ExperimentalStdlibApi::class)

package at.asitplus.awesn1.hardening

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.Asn1Real
import at.asitplus.awesn1.encoding.decodeAsn1VarULong
import at.asitplus.awesn1.encoding.decodeToDouble
import at.asitplus.awesn1.encoding.decodeToFloat
import at.asitplus.awesn1.encoding.decodeToLong
import at.asitplus.awesn1.encoding.fromTwosComplementByteArray
import at.asitplus.awesn1.encoding.toAsn1VarInt
import at.asitplus.awesn1.encoding.toUnsignedByteArray
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import at.asitplus.testballoon.matrix.matrixSuite

// Suite names preserve the original finding identifiers.
val real_decode_double_nan_for_representable_values by matrixSuite {
    "A wide mantissa and compensating negative exponent convert to a finite value" {
        val content = "81fbb8".hexToByteArray() + ByteArray(138) { 0xff.toByte() }
        val primitive = Asn1Primitive(Asn1Element.Tag.REAL, content)
        primitive.decodeToDouble() shouldBe 256.0
        primitive.decodeToFloat() shouldBe 256.0f
    }

    "The sign survives wide-mantissa conversion" {
        val content = "c1fbb8".hexToByteArray() + ByteArray(138) { 0xff.toByte() }
        Asn1Primitive(Asn1Element.Tag.REAL, content).decodeToDouble() shouldBe -256.0
    }

    "An ordinary finite REAL still converts correctly" {
        Asn1Primitive(Asn1Element.Tag.REAL, "800003".hexToByteArray()).decodeToDouble() shouldBe 3.0
    }

    "A genuine NaN remains NaN" {
        Asn1Primitive(Asn1Element.Tag.REAL, byteArrayOf(0x42)).decodeToDouble().isNaN() shouldBe true
    }
}

val RealBinary64Rounding by matrixSuite {
    for ((mantissa, expected) in listOf(
        "20000000000001" to 9007199254740992.0,
        "20000000000003" to 9007199254740996.0,
        "3fffffffffffff" to 18014398509481984.0,
        "40000000000003" to 18014398509481988.0,
    )) {
        "Mantissa $mantissa rounds to $expected using nearest-even binary64 rounding" {
            Asn1Real(Asn1Integer.fromUnsignedByteArray(mantissa.hexToByteArray()), 0).toDouble() shouldBe expected
        }
    }
}

val real_base_factor_bits_ignored_lenient by matrixSuite {
    for ((content, expected) in listOf(
        "900101" to 8.0,
        "a00101" to 16.0,
        "880001" to 4.0,
        "d40101" to -16.0,
    )) {
        "Lenient decoding applies the base, scaling factor, and sign of $content" {
            Asn1Real.decodeFromAsn1ContentBytes(content.hexToByteArray(), lenient = true).toDouble() shouldBe expected
        }

        "Strict decoding rejects noncanonical REAL content $content" {
            shouldThrow<Asn1Exception> { Asn1Real.decodeFromAsn1ContentBytes(content.hexToByteArray()) }
        }
    }
}

val real_lenient_exponent_still_der_strict by matrixSuite {
    "A minimal REAL exponent still decodes leniently" {
        Asn1Real.decodeFromAsn1ContentBytes("800101".hexToByteArray(), lenient = true).toDouble() shouldBe 2.0
    }

    for ((content, expected) in listOf(
        "81000101" to 2.0,
        "8302000101" to 2.0,
        "81ffff01" to 0.5,
    )) {
        "Lenient decoding accepts the padded REAL exponent in $content" {
            Asn1Real.decodeFromAsn1ContentBytes(content.hexToByteArray(), lenient = true).toDouble() shouldBe expected
        }

        "Strict decoding rejects the padded REAL exponent in $content" {
            shouldThrow<Asn1Exception> { Asn1Real.decodeFromAsn1ContentBytes(content.hexToByteArray()) }
        }
    }
}

val varint_ulong_decode_overflow_wrap by matrixSuite {
    for (content in listOf("82ffffffffffffffff01", "90808080808080808000")) {
        "An overflowing ULong varint $content is rejected before it can wrap" {
            shouldThrow<IllegalArgumentException> { content.hexToByteArray().decodeAsn1VarULong() }
        }
    }

    "The maximum legal ten-octet ULong varint accepts all seven bits in its final octet" {
        val content = "81ffffffffffffffff7f".hexToByteArray()
        val (value, consumed) = content.decodeAsn1VarULong()
        value shouldBe ULong.MAX_VALUE
        consumed shouldBe content
        value.toAsn1VarInt() shouldBe content
    }
}

val lenient_empty_integer_divergence by matrixSuite {
    "Lenient empty signed INTEGER decoding returns zero" {
        Int.fromTwosComplementByteArray(byteArrayOf(), lenient = true) shouldBe 0
        Long.fromTwosComplementByteArray(byteArrayOf(), lenient = true) shouldBe 0L
        Asn1Integer.fromTwosComplement(byteArrayOf(), lenient = true) shouldBe Asn1Integer.ZERO
        Asn1Primitive(Asn1Element.Tag.INT, byteArrayOf()).decodeToLong(lenient = true) shouldBe 0L
    }

    "Strict empty signed INTEGER decoding remains invalid" {
        shouldThrow<IllegalArgumentException> { Int.fromTwosComplementByteArray(byteArrayOf()) }
        shouldThrow<IllegalArgumentException> { Long.fromTwosComplementByteArray(byteArrayOf()) }
    }
}

val tounsignedbytearray_zero_emits_empty by matrixSuite {
    "Zero retains a magnitude octet" {
        0L.toUnsignedByteArray().toHexString() shouldBe "00"
    }

    "A positive magnitude drops only its sign-padding octet" {
        1L.toUnsignedByteArray().toHexString() shouldBe "01"
        128L.toUnsignedByteArray().toHexString() shouldBe "80"
        256L.toUnsignedByteArray().toHexString() shouldBe "0100"
    }
}
