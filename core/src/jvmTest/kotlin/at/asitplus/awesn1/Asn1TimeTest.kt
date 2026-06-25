package at.asitplus.awesn1

import at.asitplus.awesn1.encoding.decodeGeneralizedTimeFromAsn1ContentBytes
import at.asitplus.awesn1.encoding.decodeToInstant
import at.asitplus.awesn1.encoding.decodeUtcTimeFromAsn1ContentBytes
import at.asitplus.awesn1.encoding.encodeToAsn1GeneralizedTimePrimitive
import at.asitplus.awesn1.encoding.encodeToAsn1UtcTimePrimitive
import at.asitplus.awesn1.encoding.parse
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.property.Arb
import io.kotest.property.arbitrary.javaInstant
import java.time.Instant
import kotlin.time.toKotlinInstant
import kotlin.time.Instant as KotlinInstant

val Asn1TimeTest by matrixSuite {

    val utcLowerBound = kotlin.time.Instant.parse("1950-01-01T00:00:00Z")
    val utcUpperBound = kotlin.time.Instant.parse("2050-01-01T00:00:00Z")
    compact("Asn1Time test equals and hashCode") - {
        property(
            /* Subtract random number from upper bound, which is used to add seconds to val [later] */
            Arb.javaInstant(Instant.MIN, Instant.MAX.minusSeconds(824046715L)),
        ) test { instant ->
            val now = instant
            val then = instant.plusSeconds(500L)
            val later = instant.plusSeconds(824046715L)

            val asn1Time = Asn1Time(now.toKotlinInstant())
            val asn1Time1 = Asn1Time(then.toKotlinInstant())
            val asn1Time2 = Asn1Time(then.toKotlinInstant().secondsCapped(), Asn1Time.Format.UTC)
            val asn1Time3 = Asn1Time(later.toKotlinInstant(), Asn1Time.Format.GENERALIZED)

            asn1Time shouldBe asn1Time
            asn1Time.hashCode() shouldBe asn1Time.hashCode()
            asn1Time1 shouldBe asn1Time1
            asn1Time1.hashCode() shouldBe asn1Time1.hashCode()
            asn1Time2 shouldBe asn1Time2
            asn1Time2.hashCode() shouldBe asn1Time2.hashCode()
            asn1Time3 shouldBe asn1Time3
            asn1Time3.hashCode() shouldBe asn1Time3.hashCode()

            if (then.toKotlinInstant() in utcLowerBound..<utcUpperBound) {
                asn1Time1 shouldBe asn1Time2
                asn1Time1.hashCode() shouldBe asn1Time2.hashCode()
            } else {
                asn1Time1 shouldNotBe asn1Time2
                asn1Time1.hashCode() shouldNotBe asn1Time2.hashCode()
                asn1Time1 shouldBe Asn1Time(then.toKotlinInstant(), Asn1Time.Format.GENERALIZED)
                asn1Time1.hashCode() shouldBe Asn1Time(then.toKotlinInstant(), Asn1Time.Format.GENERALIZED).hashCode()
            }

            asn1Time shouldNotBe asn1Time1
            asn1Time.hashCode() shouldNotBe asn1Time1.hashCode()
            asn1Time shouldNotBe asn1Time3
            asn1Time.hashCode() shouldNotBe asn1Time3.hashCode()
            asn1Time2 shouldNotBe asn1Time3
            asn1Time2.hashCode() shouldNotBe asn1Time3.hashCode()
        }
    }
}

    /** Wraps [body] (ASCII) as a DER GENERALIZED TIME primitive (tag 0x18, single-byte length). */
    private fun time(body: String): ByteArray {
        val b = body.encodeToByteArray()
        require(b.size < 128)
        return byteArrayOf(0x18, b.size.toByte()) + b
    }

    private fun decode(der: ByteArray) = Asn1Time.decodeFromTlv(Asn1Element.parse(der).asPrimitive())

    /**
     * Builds an [Asn1Time] from the canonical GENERALIZED TIME value [body] (e.g. `"20240102030405.05Z"`)
     * through every construction path and asserts they are all equal and round-trip to the same DER bytes:
     *  - DER:    [Asn1Time.decodeFromTlv] of the encoded primitive
     *  - String: the `Asn1Time(String)` faux-constructor (arbitrary fractional precision)
     *  - Instant: `Asn1Time(kotlin.time.Instant)` — only when the fraction fits nanosecond precision ([iso] non-null)
     *
     * Expected subtype/fraction are derived from [body] itself. Pass [iso] = `null` for fractions beyond
     * nanosecond precision, where the Instant path cannot represent the value.
     */
    private fun assertAllPaths(body: String, iso: String?) {
        val der = time(body)
        val expectedFraction = body.substringAfter('.', "").removeSuffix("Z").ifEmpty { null }

        val viaDer = decode(der)
        val viaString = Asn1Time(body)
        val viaInstant = iso?.let { Asn1Time(kotlin.time.Instant.parse(it)) }

        for (t in listOfNotNull(viaDer, viaString, viaInstant)) {
            t shouldBe viaDer
            t.hashCode() shouldBe viaDer.hashCode()
            t.encodeToTlv().derEncoded shouldBe der
            if (expectedFraction == null) t.shouldBeInstanceOf<Asn1Time.SecondsCapped>()
            else t.shouldBeInstanceOf<Asn1Time.Fractional>().fractionalSeconds shouldBe expectedFraction
        }
    }

    val Asn1TimeFocusedTest by matrixSuite {

        // Each case is constructed via DER + String + (when fraction <= nanosecond) Kotlin Instant, and the
        // results are asserted equal and byte-identical on re-encode.

        "whole-second GENERALIZED (>= 2050 so format matches across paths)" {
            assertAllPaths("20520101000000Z", iso = "2052-01-01T00:00:00Z")
        }

        "fraction .5" {
            assertAllPaths("20240102030405.5Z", iso = "2024-01-02T03:04:05.5Z")
        }

        "fraction .05 (leading zero preserved)" {
            assertAllPaths("20240102030405.05Z", iso = "2024-01-02T03:04:05.05Z")
        }

        "fraction .123456789 (max nanosecond precision)" {
            assertAllPaths("20240102030405.123456789Z", iso = "2024-01-02T03:04:05.123456789Z")
        }

        "fraction .1234567890123 (beyond nanosecond; DER + String only)" {
            assertAllPaths("20240102030405.1234567890123Z", iso = null)
        }

        "fraction .0123456789012 (beyond nanosecond, leading zero; DER + String only)" {
            assertAllPaths("20240102030405.0123456789012Z", iso = null)
        }

        // ---- path-specific cases without a clean three-way equivalence ----

        "UTC parses to SecondsCapped UTC (String/Instant paths are GeneralizedTime-only)" {
            val t = decode(byteArrayOf(0x17, 13) + "240102030405Z".encodeToByteArray())
            t.shouldBeInstanceOf<Asn1Time.SecondsCapped>()
            t.format shouldBe Asn1Time.Format.UTC
        }

        "sub-second Instant + UTC override is rejected" {
            shouldThrow<IllegalArgumentException> {
                Asn1Time(kotlin.time.Instant.parse("2024-01-02T03:04:05.050Z"), Asn1Time.Format.UTC)
            }
        }
    }
