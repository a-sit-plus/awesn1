package at.asitplus.awesn1.serialization.api

import at.asitplus.awesn1.hardening.DerLimitFixtures
import at.asitplus.awesn1.hardening.assertExactLimitSucceedsAndBelowLimitThrows
import at.asitplus.awesn1.io.decodeFromSource
import at.asitplus.awesn1.serialization.DER
import at.asitplus.testballoon.matrix.matrixSuite
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
}

private fun ByteArray.toBuffer() = Buffer().also { it.write(this) }
