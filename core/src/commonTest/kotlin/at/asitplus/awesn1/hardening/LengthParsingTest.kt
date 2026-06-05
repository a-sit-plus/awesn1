package at.asitplus.awesn1.at.asitplus.awesn1

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain

val FocusedDERlengthparsing by matrixSuite {
    "accepts short-form length" {
        Asn1Element.parseFromDerHexString("04 03 AA BB CC") shouldBe
                Asn1.OctetString("AABBCC".hexToByteArray(HexFormat.UpperCase))
    }

    "accepts long-form length when required" {
        val content = "AA".repeat(128)

        Asn1Element.parseFromDerHexString("04 81 80 $content") shouldBe
                Asn1.OctetString(content.hexToByteArray(HexFormat.UpperCase))
    }

    "rejects indefinite length" {
        shouldThrow<Asn1Exception> {
            Asn1Element.parseFromDerHexString("04 80 AA BB 00 00")
        }.message shouldBe "Illegal DER length encoding; indefinite length is not allowed"
    }

    "rejects long-form length used unnecessarily" {
        val content = "AA".repeat(127)

        shouldThrow<Asn1Exception> {
            Asn1Element.parseFromDerHexString("04 81 7F $content")
        }.message shouldBe "Illegal DER length encoding; length 127 < 128 using long form"
    }

    "rejects length-of-length zero" {
        shouldThrow<Asn1Exception> {
            Asn1Element.parseFromDerHexString("04 80")
        }.message shouldBe "Illegal DER length encoding; indefinite length is not allowed"
    }

    "rejects missing long-form length octet" {
        shouldThrow<Asn1Exception> {
            Asn1Element.parseFromDerHexString("04 81")
        }.message shouldBe "Can't decode length. End of input reached before all length bytes were read"
    }

    "rejects partial long-form length octets" {
        shouldThrow<Asn1Exception> {
            Asn1Element.parseFromDerHexString("04 82 01")
        }.message shouldBe "Can't decode length. End of input reached before all length bytes were read"
    }

    "rejects overlong long-form length" {
        val content = "AA".repeat(128)

        shouldThrow<Asn1Exception> {
            Asn1Element.parseFromDerHexString("04 82 00 80 $content")
        }.message shouldBe "Illegal DER length encoding; long form length with leading zeros"
    }

    "rejects declared length beyond input" {
        shouldThrow<Asn1Exception> {
            Asn1Element.parseFromDerHexString("04 05 AA BB")
        }.message shouldBe "Length of ASN.1 element exceeds limit: 7 > 4"
    }

    "rejects complete long-form length with missing content" {
        shouldThrow<Asn1Exception> {
            Asn1Element.parseFromDerHexString("04 82 01 00 AA")
        }
    }

    "rejects length integer overflow" {
        shouldThrow<Asn1Exception> {
            Asn1Element.parseFromDerHexString("04 88 FF FF FF FF FF FF FF FF AA")
        }.message shouldBe "Unsupported length >Long.MAX_VALUE: 18446744073709551615"
    }

    data(
        "rejects non-minimal high-tag-number base128 encodings",
        listOf(
            HighTagNumberVector(
                name = "tag-31-leading-zero-group",
                hex = "9F 80 1F 00",
                note = "Tag 31 encoded as 80 1F is non-minimal; canonical is 1F."
            ),
            HighTagNumberVector(
                name = "tag-31-two-leading-zero-groups",
                hex = "9F 80 80 1F 00",
                note = "Tag 31 encoded with two redundant leading zero base-128 groups."
            ),
            HighTagNumberVector(
                name = "tag-128-leading-zero-group",
                hex = "9F 80 81 00 00",
                note = "Tag 128 encoded as 80 81 00 is non-minimal; canonical is 81 00."
            ),
            HighTagNumberVector(
                name = "tag-16384-leading-zero-group",
                hex = "9F 80 81 80 00 00",
                note = "Tag 16384 encoded with redundant leading zero group; canonical is 81 80 00."
            ),
            HighTagNumberVector(
                name = "application-constructed-tag-31-leading-zero-group",
                hex = "7F 80 1F 00",
                note = "Same non-minimal tag-number encoding, but with application constructed class."
            )
        ),
        nameFn = { _, it -> it.name }
    ) test { (_, hex, note) ->
        withClue(note) {
            shouldThrow<Asn1Exception> { Asn1Element.parseFromDerHexString(hex) }.message.shouldContain(
                "is not minimally encoded. Encoded bytes are: ${
                    hex.substring(0,hex.length-3).replace(" ", "").lowercase()
                }"
            )
        }
    }

}

private data class HighTagNumberVector(
    val name: String,
    val hex: String,
    val note: String,
)