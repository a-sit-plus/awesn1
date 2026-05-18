package at.asitplus.awesn1.at.asitplus.awesn1

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

val DerTagParsing by testSuite {
    "rejects universal tag zero" - {
        withData(
            "primitive incomplete" to "00",
            "primitive complete" to "00 00",
            "constructed incomplete" to "20",
            "constructed complete" to "20 00",
            compact = false
        ) { hex ->
            shouldThrow<Asn1Exception> {
                Asn1Element.parseFromDerHexString(hex)
            }
        }
    }

    "accepts complete non-universal tag zero" - {
        withData(
            "application primitive" to "40 00",
            "application constructed" to "60 00",
            "context-specific primitive" to "80 00",
            "context-specific constructed" to "A0 00",
            "private primitive" to "C0 00",
            "private constructed" to "E0 00",
            compact = false
        ) { hex ->
            Asn1Element.parseFromDerHexString(hex).toDerHexString() shouldBe hex.replace(" ", "")
        }
    }

    "rejects incomplete non-universal tag zero TLVs" - {
        withData(
            "application primitive" to "40",
            "application constructed" to "60",
            "context-specific primitive" to "80",
            "context-specific constructed" to "A0",
            "private primitive" to "C0",
            "private constructed" to "E0",
            compact = false
        ) { hex ->
            shouldThrow<Asn1Exception> {
                Asn1Element.parseFromDerHexString(hex)
            }
        }
    }

    "accepts high-tag-number 31" {
        Asn1Element.parseFromDerHexString("1F 1F 00").tag shouldBe
                Asn1Element.Tag(31uL, "1F1F".hexToByteArray(HexFormat.UpperCase))
    }

    "accepts high-tag-number 128" {
        Asn1Element.parseFromDerHexString("1F 81 00 00").tag shouldBe
                Asn1Element.Tag(128uL, "1F8100".hexToByteArray(HexFormat.UpperCase))
    }

    "rejects non-minimal high-tag-number form for tag below 31" {
        shouldThrow<Asn1Exception> {
            Asn1Element.parseFromDerHexString("1F 01 00")
        }.message shouldBe "Tag number 1 must be encoded in low-tag-number form. Encoded bytes are: 1f01"
    }

    "EOF" - {
        "no length after tag" {
            shouldThrow<Asn1Exception> {
                Asn1Element.parseFromDerHexString("1F 81 80 00")
            }.message shouldBe "Source exhausted"
        }

        "incomplete high-tag-number form" {
            shouldThrow<Asn1Exception> {
                Asn1Element.parseFromDerHexString("1F 81")
            }.message shouldBe "Unterminated ASN.1 unsigned varint"
        }

        "incomplete high-tag-number form with additional byte" {
            shouldThrow<Asn1Exception> {
                Asn1Element.parseFromDerHexString("1F 81 80")
            }.message shouldBe "Unterminated ASN.1 unsigned varint"
        }
    }
}
