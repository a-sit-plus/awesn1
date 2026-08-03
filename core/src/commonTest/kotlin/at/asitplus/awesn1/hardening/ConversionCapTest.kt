package at.asitplus.awesn1.at.asitplus.awesn1.hardening

import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

/**
 * Verifies the conversion caps that bound the O(n^2) base-256 <-> base-10 work:
 *  - [Asn1Integer.toDecimalString] / [Asn1Integer.fromDecimalString] enforce a magnitude-byte cap,
 *  - [Asn1Integer.toString] stays bounded and non-throwing above the cap,
 *  - [ObjectIdentifier] rejects an oversized sub-identifier when stringifying.
 */
val ConversionCapTests by matrixSuite {

    // magnitude of `bytes` bytes, leading byte 0x01 so nothing is trimmed
    fun magnitudeOf(bytes: Int) = Asn1Integer.fromUnsignedByteArray(ByteArray(bytes).also { it[0] = 0x01 })

    "toDecimalString throws above the default cap and succeeds when the cap is raised" {
        val limit = 32 * 1024
        val overCap = magnitudeOf(limit + 1)
        shouldThrow<Asn1Exception> { overCap.toDecimalString(maxMagnitudeBytes = limit) }
        // raising the cap past the actual size makes it convertible again
        overCap.toDecimalString(maxMagnitudeBytes = limit * 2).isNotEmpty() shouldBe true
    }

    "toDecimalString accepts a value exactly at the cap" {
        val limit = 32 * 1024
        magnitudeOf(limit).toDecimalString(maxMagnitudeBytes = limit).isNotEmpty() shouldBe true
    }

    "toString is bounded and non-throwing" {
        val overCap = magnitudeOf(1024 * 1024)
        shouldThrow<Asn1Exception> {
            overCap.toDecimalString() // must not blow up nor run the full conversion
        }
        shouldNotThrowAny { overCap.toString() } shouldBe
                "[truncated, 1048576 bytes total] 0x01${"00".repeat(47)}…"
    }

    "toString renders the exact value at or below the cap" {
        Asn1Integer(0x123456789).toString() shouldBe "0x0123456789"
        Asn1Integer(-0x987654321L).toString() shouldBe "-0x0987654321"
    }

    "toString truncates only above 48 bytes for both signs" {
        val exact = ByteArray(48).also { it[0] = 0x01 }
        val over = ByteArray(49).also { it[0] = 0x01 }
        for ((sign, prefix) in listOf(Asn1Integer.Sign.POSITIVE to "0x", Asn1Integer.Sign.NEGATIVE to "-0x")) {
            Asn1Integer.fromByteArray(exact, sign).toString() shouldBe prefix + "01" + "00".repeat(47)
            Asn1Integer.fromByteArray(over, sign).toString() shouldBe "[truncated, 49 bytes total] " +prefix + "01" + "00".repeat(47) + "…"
            Asn1Integer.fromByteArray(over, sign).toHexString() shouldBe prefix + "01" + "00".repeat(48)
        }
    }

    "fromDecimalString rejects an over-cap digit string up front" {
        val limit = 80000
        val tooManyDigits = "9".repeat(limit * 3) // far past the digit budget
        shouldThrow<Asn1Exception> { Asn1Integer.fromDecimalString(tooManyDigits, maxInputLength = limit) }
    }

    "fromDecimalString round-trips a realistic RSA-4096-scale value" {
        // 1233 decimal digits ~ 512-byte modulus; well within the cap.
        val digits = "1234567890".repeat(123) + "7"
        Asn1Integer.fromDecimalString(digits).toDecimalString() shouldBe digits
    }

    "ObjectIdentifier rejects a sub-identifier beyond the cap" {
        // one giant, minimally-encoded base-128 sub-identifier: 0x81, then continuation bytes, then a terminator.
        val len = ((ObjectIdentifier.MAX_SUBIDENTIFIER_BYTES * 8 + 6) / 7) + 11
        val giant = ByteArray(len).also { arr ->
            arr[0] = 0x81.toByte()                       // first byte: high bit set, not 0x80 (minimal)
            for (i in 1 until len - 1) arr[i] = 0x80.toByte() // continuation bytes (high bit set)
            arr[len - 1] = 0x01                          // terminator: high bit clear
        }
        shouldThrow<Asn1Exception> { ObjectIdentifier.decodeFromAsn1ContentBytes(giant).nodes }
    }

    "ObjectIdentifier still accepts a large-but-legal sub-identifier (2.25 UUID-scale)" {
        // a 20-byte sub-identifier (larger than any real UUID arc, still < cap) must parse fine
        val len = 20
        val subid = ByteArray(len).also { arr ->
            arr[0] = 0x81.toByte()
            for (i in 1 until len - 1) arr[i] = 0x80.toByte()
            arr[len - 1] = 0x01
        }
        ObjectIdentifier.decodeFromAsn1ContentBytes(subid).nodes.isNotEmpty() shouldBe true
    }
}
