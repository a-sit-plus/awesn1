package at.asitplus.awesn1.at.asitplus.awesn1

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

val FocusedDerlengthParsing by testSuite {
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
}
