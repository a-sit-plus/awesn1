package at.asitplus.awesn1.serialization.api

import at.asitplus.awesn1.hardening.DerLimitFixtures
import at.asitplus.awesn1.hardening.assertExactLimitSucceedsAndBelowLimitThrows
import at.asitplus.awesn1.io.decodeFromSource
import at.asitplus.awesn1.serialization.DER
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.builtins.serializer
import kotlinx.io.Buffer

val KxsIoDerLimitPublicApiTest by matrixSuite {
    "configured Der source APIs enforce total DER input limits" - {
        "decodeFromSource reified convenience API" {
            assertExactLimitSucceedsAndBelowLimitThrows(
                exactLimit = DerLimitFixtures.singleIntegerLimit,
                belowLimit = DerLimitFixtures.singleIntegerBelowLimit,
                expected = 1,
            ) { limit ->
                DER { maxInputLength = limit }.decodeFromSource<Int>(DerLimitFixtures.singleIntegerDer.toBuffer())
            }
        }

        "decodeFromSource with explicit deserializer" {
            assertExactLimitSucceedsAndBelowLimitThrows(
                exactLimit = DerLimitFixtures.singleIntegerLimit,
                belowLimit = DerLimitFixtures.singleIntegerBelowLimit,
                expected = 1,
            ) { limit ->
                DER { maxInputLength = limit }.decodeFromSource(Int.serializer(), DerLimitFixtures.singleIntegerDer.toBuffer())
            }
        }
    }

    "the limit parameter tightens the bound (configured maximum left at default)" {
        assertExactLimitSucceedsAndBelowLimitThrows(
            exactLimit = DerLimitFixtures.singleIntegerLimit,
            belowLimit = DerLimitFixtures.singleIntegerBelowLimit,
            expected = 1,
        ) { limit ->
            DER.decodeFromSource<Int>(DerLimitFixtures.singleIntegerDer.toBuffer(), limit = limit)
        }
    }

    "the limit parameter is clamped to the configured maxInputLength and can never exceed it" {
        // a generous explicit limit cannot lift a too-small configured maximum
        shouldThrow<Throwable> {
            DER { maxInputLength = DerLimitFixtures.singleIntegerBelowLimit }
                .decodeFromSource<Int>(DerLimitFixtures.singleIntegerDer.toBuffer(), limit = Long.MAX_VALUE)
        }
        // but it still succeeds when the configured maximum is sufficient
        DER { maxInputLength = DerLimitFixtures.singleIntegerLimit }
            .decodeFromSource<Int>(DerLimitFixtures.singleIntegerDer.toBuffer(), limit = Long.MAX_VALUE) shouldBe 1
    }
}

private fun ByteArray.toBuffer() = Buffer().also { it.write(this) }
