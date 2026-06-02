package at.asitplus.awesn1.hardening

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.encoding.decodeFromDer
import at.asitplus.awesn1.encoding.decodeFromDerOrNull
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.encoding.parseAll
import at.asitplus.awesn1.encoding.parseFirst
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

val CoreDerLimitPublicApiTest by matrixSuite {
    "byte array parsing APIs enforce total DER input limits" - {
        "parse" {
            assertExactLimitSucceedsAndBelowLimitThrows(
                exactLimit = DerLimitFixtures.singleElementLimit,
                belowLimit = DerLimitFixtures.singleElementBelowLimit,
                expected = DerLimitFixtures.singleElement,
            ) { limit ->
                Asn1Element.parse(DerLimitFixtures.singleElementDer, limit)
            }
        }

        "parseAll" {
            assertExactLimitSucceedsAndBelowLimitThrows(
                exactLimit = DerLimitFixtures.multiElementLimit,
                belowLimit = DerLimitFixtures.multiElementBelowLimit,
                expected = DerLimitFixtures.multiElements,
            ) { limit ->
                Asn1Element.parseAll(DerLimitFixtures.multiElementDer, limit)
            }
        }

        "parseFirst" {
            val (element, remaining) = Asn1Element.parseFirst(
                DerLimitFixtures.singleElementDer,
                DerLimitFixtures.singleElementLimit,
            )
            element shouldBe DerLimitFixtures.singleElement
            remaining.toList() shouldBe emptyList()

            shouldThrow<Asn1Exception> {
                Asn1Element.parseFirst(
                    DerLimitFixtures.singleElementDer,
                    DerLimitFixtures.singleElementBelowLimit,
                )
            }
        }
    }

    "hex string parsing API enforces total DER input limits" {
        assertExactLimitSucceedsAndBelowLimitThrows(
            exactLimit = DerLimitFixtures.singleElementLimit,
            belowLimit = DerLimitFixtures.singleElementBelowLimit,
            expected = DerLimitFixtures.singleElement,
        ) { limit ->
            Asn1Element.parseFromDerHexString(DerLimitFixtures.singleElementHex, limit)
        }
    }

    "decodable byte array APIs enforce total DER input limits" - {
        "decodeFromDer" {
            assertExactLimitSucceedsAndBelowLimitThrows(
                exactLimit = DerLimitFixtures.singleIntegerLimit,
                belowLimit = DerLimitFixtures.singleIntegerBelowLimit,
                expected = DerLimitFixtures.singleIntegerValue,
            ) { limit ->
                Asn1Integer.decodeFromDer(DerLimitFixtures.singleIntegerDer, limit)
            }
        }

        "decodeFromDerOrNull" {
            assertExactLimitSucceedsAndBelowLimitReturnsNull(
                exactLimit = DerLimitFixtures.singleIntegerLimit,
                belowLimit = DerLimitFixtures.singleIntegerBelowLimit,
                expected = DerLimitFixtures.singleIntegerValue,
            ) { limit ->
                Asn1Integer.decodeFromDerOrNull(DerLimitFixtures.singleIntegerDer, limit)
            }
        }
    }
}
