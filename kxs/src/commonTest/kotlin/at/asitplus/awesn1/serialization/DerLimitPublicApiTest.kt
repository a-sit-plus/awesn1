package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.hardening.DerLimitFixtures
import at.asitplus.awesn1.hardening.assertExactLimitSucceedsAndBelowLimitThrows
import at.asitplus.testballoon.matrix.matrixSuite
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.decodeFromHexString

val DerLimitPublicApiTest by matrixSuite {
    "configured Der byte array APIs enforce total DER input limits" - {
        "decodeFromByteArray with explicit serializer" {
            assertExactLimitSucceedsAndBelowLimitThrows(
                exactLimit = DerLimitFixtures.singleIntegerLimit,
                belowLimit = DerLimitFixtures.singleIntegerBelowLimit,
                expected = 1,
            ) { limit ->
                DER { maxInputLength = limit }.decodeFromByteArray(Int.serializer(), DerLimitFixtures.singleIntegerDer)
            }
        }

        "decodeFromDer reified convenience API" {
            assertExactLimitSucceedsAndBelowLimitThrows(
                exactLimit = DerLimitFixtures.singleIntegerLimit,
                belowLimit = DerLimitFixtures.singleIntegerBelowLimit,
                expected = 1,
            ) { limit ->
                DER { maxInputLength = limit }.decodeFromDer<Int>(DerLimitFixtures.singleIntegerDer)
            }
        }

        "decodeFromHexString" {
            assertExactLimitSucceedsAndBelowLimitThrows(
                exactLimit = DerLimitFixtures.singleIntegerLimit,
                belowLimit = DerLimitFixtures.singleIntegerBelowLimit,
                expected = 1,
            ) { limit ->
                DER { maxInputLength = limit }.decodeFromHexString<Int>(DerLimitFixtures.singleIntegerHex)
            }
        }
    }
}
