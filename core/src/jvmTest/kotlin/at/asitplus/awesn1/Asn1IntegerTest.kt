package at.asitplus.awesn1

import at.asitplus.awesn1.encoding.decodeToAsn1Integer
import at.asitplus.awesn1.encoding.encodeToAsn1Primitive
import at.asitplus.awesn1.encoding.parse
import at.asitplus.testballoon.matrix.matrixSuite

import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeTypeOf
import io.kotest.property.Arb
import io.kotest.property.arbitrary.*
import java.math.BigInteger as JavaBigInteger

private fun UByteArray.stripLeadingZeros() =
    when (val i = indexOfFirst { it != 0x00u.toUByte() }) {
        -1 -> ubyteArrayOf(0x00u)
        0 -> this
        else -> copyOfRange(i, size)
    }

private fun ByteArray.stripLeadingZeros() = asUByteArray().stripLeadingZeros()

val Asn1IntegerTest by matrixSuite {
    "Encoding: Negative" {
        val result =
            Asn1Integer(-20).encodeToAsn1Primitive()
        result.toDerHexString() shouldBe "02 01 EC".replace(" ", "")
    }
    "Encoding: Large Positive" {
        val result =
            Asn1Integer(0xEC).encodeToAsn1Primitive()
        result.toDerHexString() shouldBe "02 02 00 EC".replace(" ", "")
    }
    "Decoding: Negative" {
        val result =
            (Asn1Element.parse(ubyteArrayOf(0x02u, 0x01u, 0xECu).toByteArray()) as Asn1Primitive)
                .decodeToAsn1Integer()
        result shouldBe Asn1Integer(-20)
    }
    "Decoding: Large Positive" {
        val result =
            (Asn1Element.parse(ubyteArrayOf(0x02u, 0x02u, 0x00u, 0xECu).toByteArray()) as Asn1Primitive)
                .decodeToAsn1Integer()
        result shouldBe Asn1Integer(0xEC)
    }
    "From String: Negative Zero" {
        Asn1Integer.fromDecimalString("-0").let {
            it.shouldBeTypeOf<Asn1Integer.Positive>()
            it.isZero() shouldBe true
            it shouldBe Asn1Integer(0)
            it shouldBe Asn1Integer.ZERO
            it.magnitude shouldBe byteArrayOf(0x00)
        }
    }
    "UVarInt Operations" - {
        "Fixed values" - {
            "XOR producing two zero high bytes" {
                (
                        VarUInt(ubyteArrayOf(0x80u, 0x7Fu, 0x03u)) xor
                                VarUInt(ubyteArrayOf(0x80u, 0x7Fu, 0x05u))
                        ).words shouldBe ubyteArrayOf(0x06u)
            }
            "AND producing two zero high bytes" {
                (
                        VarUInt(ubyteArrayOf(0x80u, 0x4Fu, 0x15u)) and
                                VarUInt(ubyteArrayOf(0x03u, 0xA0u, 0x34u))
                        ).words shouldBe ubyteArrayOf(0x14u)
            }
            "Left Shift producing a zero high byte" {
                VarUInt(ubyteArrayOf(0x18u, 0x43u)).shl(3).words shouldBe ubyteArrayOf(0xC2u, 0x18u)
            }
            "Right Shift producing a zero high byte" {
                VarUInt(ubyteArrayOf(0x05u, 0xFCu)).shr(3).words shouldBe ubyteArrayOf(0xBFu)
            }
        }
        compact("Random values") - {
            property("bytes", Arb.byteArray(Arb.int(100, 200), Arb.byte()), iterations = 100) - { bytes ->
                val bigint = JavaBigInteger(1, bytes)
                val varuint = VarUInt(bytes)
                property("Left Bitshift", Arb.nonNegativeInt(max = 128), iterations = 50) test { i ->
                    varuint.shl(i).words shouldBe bigint.shiftLeft(i).toByteArray().stripLeadingZeros()
                }
                property("Right Bitshift", Arb.nonNegativeInt(), iterations = 50) test { i ->
                    varuint.shr(i).words shouldBe bigint.shiftRight(i).toByteArray().stripLeadingZeros()
                }
                property(
                    "Binary Operators",
                    Arb.byteArray(Arb.int(100, 200), Arb.byte()),
                    iterations = 10
                ) test { other ->
                    val bigint2 = JavaBigInteger(1, other)
                    val varuint2 = VarUInt(other)
                    varuint.xor(varuint2).words shouldBe bigint.xor(bigint2).toByteArray().stripLeadingZeros()
                    varuint.or(varuint2).words shouldBe bigint.or(bigint2).toByteArray().stripLeadingZeros()
                    varuint.and(varuint2).words shouldBe bigint.and(bigint2).toByteArray().stripLeadingZeros()
                }
            }
        }
    }
    "Java BigInteger from and to Asn1Integer" - {
        data(
            "Specific values",
            listOf(
                Triple("Zero", JavaBigInteger.ZERO, Asn1Integer(0)),
                Triple("Zero from Long", JavaBigInteger.valueOf(0L), Asn1Integer(0uL)),
                Triple("One", JavaBigInteger.ONE, Asn1Integer(1)),
                Triple("Negative One", JavaBigInteger.ONE.unaryMinus(), Asn1Integer(-1)),
            ),
            nameFn = { _, it -> it.first },
        ) test { (_, bigint, asn1int) ->
            bigint.toAsn1Integer() shouldBe asn1int
            asn1int.toJavaBigInteger() shouldBe bigint
        }
        compact("Generic values") - {
            property("positive", Arb.positiveLong(), iterations = 2500) test { value ->
                val bigint = JavaBigInteger.valueOf(value)
                val asn1int = Asn1Integer(value)
                asn1int.shouldBeTypeOf<Asn1Integer.Positive>()
                bigint.toAsn1Integer() shouldBe asn1int
                asn1int.toJavaBigInteger() shouldBe bigint
            }
            property("non-positive", Arb.nonPositiveLong(), iterations = 2500) test { value ->
                val bigint = JavaBigInteger.valueOf(value)
                val asn1int = Asn1Integer(value)
                if (value < 0)
                    asn1int.shouldBeTypeOf<Asn1Integer.Negative>()
                bigint.toAsn1Integer() shouldBe asn1int
                asn1int.toJavaBigInteger() shouldBe bigint
            }
            property("negative-bytes", Arb.byteArray(Arb.int(1500..2500), Arb.byte()), iterations = 500) test { bytes ->
                val bigint = JavaBigInteger(-1, bytes)
                val asn1int = Asn1Integer.fromByteArray(bytes, Asn1Integer.Sign.NEGATIVE)
                if (!asn1int.isZero())
                    asn1int.shouldBeTypeOf<Asn1Integer.Negative>()
                bigint.toAsn1Integer() shouldBe asn1int
                asn1int.toJavaBigInteger() shouldBe bigint
            }
            property(
                "positive-bytes",
                Arb.byteArray(Arb.int(1500..2500), Arb.byte()),
                iterations = 1000
            ) test { bytes ->
                val bigint = JavaBigInteger(1, bytes)
                val asn1int = Asn1Integer.fromUnsignedByteArray(bytes)
                asn1int.shouldBeTypeOf<Asn1Integer.Positive>()
                bigint.toAsn1Integer() shouldBe asn1int
                asn1int.toJavaBigInteger() shouldBe bigint
            }
        }
        compact("Equality") - {
            val arb = Arb.byteArray(Arb.int(1500..2500), Arb.byte())
            property("outer", arb, iterations = 10) - { outer ->
                val i1 = Asn1Integer.fromUnsignedByteArray(outer)
                i1 shouldBe Asn1Integer.fromUnsignedByteArray(outer)
                property("inner", arb.filterNot { it contentEquals outer }, iterations = 10) test { inner ->
                    i1 shouldNotBe Asn1Integer.fromUnsignedByteArray(inner)
                }
            }
        }
    }
}
