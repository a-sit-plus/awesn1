package at.asitplus.awesn1.hardening

import at.asitplus.awesn1.Asn1Integer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe
import java.math.BigInteger
import kotlin.random.Random
import kotlin.random.asJavaRandom
import kotlin.system.measureTimeMillis

private fun asn1Of(value: BigInteger): Asn1Integer {
    val sign = if (value.signum() < 0) Asn1Integer.Sign.NEGATIVE else Asn1Integer.Sign.POSITIVE
    val magnitude = value.abs().toByteArray() // may carry a leading 0x00; fromByteArray/VarUInt trims it
    return Asn1Integer.fromByteArray(magnitude, sign)
}

/**
 * Cross-checks the base-256 <-> base-10 conversion (both directions) against [BigInteger] as the reference
 * oracle, across a wide range of magnitudes including multi-KB (RSA/DH-class) values. Also a coarse guard that
 * the conversion is no longer pathologically quadratic at crypto-relevant sizes.
 */
val DecimalConversionTest by matrixSuite {

    "forward: toString matches BigInteger.toString across sizes" {
        val rnd = Random(1234).asJavaRandom()
        val bitSizes = listOf(1, 7, 8, 15, 16, 31, 32, 33, 63, 64, 65, 127, 255, 512, 1024, 2048, 4096, 8192, 16384, 32768)
        for (bits in bitSizes) repeat(8) {
            val magnitude = BigInteger(bits, rnd)
            for (signed in listOf(magnitude, magnitude.negate())) {
                withClue("bits=$bits value=$signed") {
                    asn1Of(signed).toDecimalString() shouldBe signed.toString()
                }
            }
        }
    }

    "reverse: fromDecimalString round-trips against BigInteger across sizes" {
        val rnd = Random(4321)
        val jrnd = rnd.asJavaRandom()
        val bitSizes = listOf(1, 8, 16, 32, 64, 128, 512, 1024, 2048, 4096, 16384, 32768)
        for (bits in bitSizes) repeat(8) {
            val v = BigInteger(bits, jrnd).let { if (rnd.nextBoolean()) it.negate() else it }
            val decimal = v.toString()
            withClue("bits=$bits value=$decimal") {
                Asn1Integer.fromDecimalString(decimal).toDecimalString() shouldBe decimal
            }
        }
    }

    "boundary values" {
        val values = listOf(
            BigInteger.ZERO, BigInteger.ONE, BigInteger.TEN, BigInteger.valueOf(-1),
            BigInteger.valueOf(255), BigInteger.valueOf(256), BigInteger.valueOf(-256),
            BigInteger.TWO.pow(63), BigInteger.TWO.pow(63).negate(),
            BigInteger.TEN.pow(9), BigInteger.TEN.pow(9) - BigInteger.ONE, BigInteger.TEN.pow(18),
        )
        for (v in values) withClue("value=$v") {
            asn1Of(v).toDecimalString() shouldBe v.toString()
            Asn1Integer.fromDecimalString(v.toString()).toDecimalString() shouldBe v.toString()
        }
    }

    "crypto-scale conversion stays fast (not pathologically quadratic)" {
        val big = BigInteger(4096 * 8, Random(99).asJavaRandom()) // 4 KB magnitude (RSA-32768-class)
        val asn1 = asn1Of(big)
        val decimal = big.toString()
        val elapsed = measureTimeMillis {
            repeat(20) {
                asn1.toDecimalString() shouldBe decimal
                Asn1Integer.fromDecimalString(decimal).toDecimalString() shouldBe decimal
            }
        }
        // Old List<Char> schoolbook rendered ~0.4 s per pass here; we must keep 20 round-trips well under 2 s.
        check(elapsed < 2000) { "conversion too slow: ${elapsed}ms for 20x 4KB round-trips" }
    }
}
