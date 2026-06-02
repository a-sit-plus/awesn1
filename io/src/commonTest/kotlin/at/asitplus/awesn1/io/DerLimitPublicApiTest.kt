package at.asitplus.awesn1.io

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.hardening.DerLimitFixtures
import at.asitplus.awesn1.hardening.assertExactLimitSucceedsAndBelowLimitThrows
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.io.Buffer

val IoDerLimitPublicApiTest by matrixSuite {
    "source parsing APIs enforce total DER input limits" - {
        "parse" {
            assertExactLimitSucceedsAndBelowLimitThrows(
                exactLimit = DerLimitFixtures.singleElementLimit,
                belowLimit = DerLimitFixtures.singleElementBelowLimit,
                expected = DerLimitFixtures.singleElement,
            ) { limit ->
                Asn1Element.parse(DerLimitFixtures.singleElementDer.toBuffer(), limit)
            }
        }

        "parseAll" {
            assertExactLimitSucceedsAndBelowLimitThrows(
                exactLimit = DerLimitFixtures.multiElementLimit,
                belowLimit = DerLimitFixtures.multiElementBelowLimit,
                expected = DerLimitFixtures.multiElements,
            ) { limit ->
                Asn1Element.parseAll(DerLimitFixtures.multiElementDer.toBuffer(), limit)
            }
        }

        "parseFirst" {
            Asn1Element.parseFirst(
                DerLimitFixtures.singleElementDer.toBuffer(),
                DerLimitFixtures.singleElementLimit,
            ) shouldBe (DerLimitFixtures.singleElement to DerLimitFixtures.singleElementLimit)

            shouldThrow<Asn1Exception> {
                Asn1Element.parseFirst(
                    DerLimitFixtures.singleElementDer.toBuffer(),
                    DerLimitFixtures.singleElementBelowLimit,
                )
            }
        }
    }

    "source read APIs enforce total DER input limits" - {
        "readAsn1Element" {
            DerLimitFixtures.singleElementDer.toBuffer()
                .readAsn1Element(DerLimitFixtures.singleElementLimit) shouldBe
                    (DerLimitFixtures.singleElement to DerLimitFixtures.singleElementLimit)

            shouldThrow<Asn1Exception> {
                DerLimitFixtures.singleElementDer.toBuffer()
                    .readAsn1Element(DerLimitFixtures.singleElementBelowLimit)
            }
        }

        "readFullyToAsn1Elements" {
            DerLimitFixtures.multiElementDer.toBuffer()
                .readFullyToAsn1Elements(DerLimitFixtures.multiElementLimit) shouldBe
                    (DerLimitFixtures.multiElements to DerLimitFixtures.multiElementLimit)

            shouldThrow<Asn1Exception> {
                DerLimitFixtures.multiElementDer.toBuffer()
                    .readFullyToAsn1Elements(DerLimitFixtures.multiElementBelowLimit)
            }
        }
    }

    "decodable source API enforces total DER input limits" {
        assertExactLimitSucceedsAndBelowLimitThrows(
            exactLimit = DerLimitFixtures.singleIntegerLimit,
            belowLimit = DerLimitFixtures.singleIntegerBelowLimit,
            expected = DerLimitFixtures.singleIntegerValue,
        ) { limit ->
            Asn1Integer.decodeFromDer(DerLimitFixtures.singleIntegerDer.toBuffer(), limit)
        }
    }
}

private fun ByteArray.toBuffer() = Buffer().also { it.write(this) }
