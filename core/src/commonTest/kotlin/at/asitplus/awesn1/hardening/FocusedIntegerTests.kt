package at.asitplus.awesn1.at.asitplus.awesn1.hardening

import at.asitplus.awesn1.*
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe


private val minimal = listOf(
    IntegerVector(
        name = "accept-zero",
        hex = "02 01 00",
        shouldAccept = true,
        note = "INTEGER 0, minimal.",
        expectedValue = Asn1Integer(0)
    ),
    IntegerVector(
        name = "accept-positive-one",
        hex = "02 01 01",
        shouldAccept = true,
        note = "INTEGER +1, minimal.",
        expectedValue = Asn1Integer(1)
    ),
    IntegerVector(
        name = "accept-positive-127",
        hex = "02 01 7F",
        shouldAccept = true,
        note = "Largest one-octet positive INTEGER.",
        expectedValue = Asn1Integer(127)
    ),
    IntegerVector(
        name = "accept-positive-128",
        hex = "02 02 00 80",
        shouldAccept = true,
        note = "+128 needs leading 00 so it is not interpreted as negative.",
        expectedValue = Asn1Integer(128)
    ),
    IntegerVector(
        name = "accept-positive-255",
        hex = "02 02 00 FF",
        shouldAccept = true,
        note = "+255 needs leading 00 because FF would otherwise be negative.",
        expectedValue = Asn1Integer(255)
    ),
    IntegerVector(
        name = "accept-positive-256",
        hex = "02 02 01 00",
        shouldAccept = true,
        note = "+256, no leading 00 needed because first value octet has sign bit clear.",
        expectedValue = Asn1Integer(256)
    ),
    IntegerVector(
        name = "accept-positive-32767",
        hex = "02 02 7F FF",
        shouldAccept = true,
        note = "+32767, minimal two-octet positive.",
        expectedValue = Asn1Integer(32767)
    ),
    IntegerVector(
        name = "accept-positive-32768",
        hex = "02 03 00 80 00",
        shouldAccept = true,
        note = "+32768 needs leading 00 to keep sign positive.",
        expectedValue = Asn1Integer(32768)
    ),

    IntegerVector(
        name = "accept-negative-one",
        hex = "02 01 FF",
        shouldAccept = true,
        note = "-1, minimal.",
        expectedValue = Asn1Integer(-1)
    ),
    IntegerVector(
        name = "accept-negative-128",
        hex = "02 01 80",
        shouldAccept = true,
        note = "-128, smallest one-octet negative INTEGER.",
        expectedValue = Asn1Integer(-128)
    ),
    IntegerVector(
        name = "accept-negative-129",
        hex = "02 02 FF 7F",
        shouldAccept = true,
        note = "-129 needs leading FF to preserve negative sign.",
        expectedValue = Asn1Integer(-129)
    ),
    IntegerVector(
        name = "accept-negative-256",
        hex = "02 02 FF 00",
        shouldAccept = true,
        note = "-256, minimal two-octet negative.",
        expectedValue = Asn1Integer(-256)
    ),
    IntegerVector(
        name = "accept-negative-32768",
        hex = "02 02 80 00",
        shouldAccept = true,
        note = "-32768, minimal two-octet negative.",
        expectedValue = Asn1Integer(-32768)
    ),
    IntegerVector(
        name = "accept-negative-32769",
        hex = "02 03 FF 7F FF",
        shouldAccept = true,
        note = "-32769 needs leading FF to preserve negative sign.",
        expectedValue = Asn1Integer(-32769)
    )
)

private val nonMinimal = listOf(
    IntegerVector(
        name = "reject-empty-integer",
        hex = "02 00",
        shouldAccept = false,
        note = "INTEGER must have at least one content octet.",
        expectedValue = Asn1Integer(0)
    ),

    IntegerVector(
        name = "reject-overlong-zero-one-leading-00",
        hex = "02 02 00 00",
        shouldAccept = false,
        note = "0 must be encoded as single 00.",
        expectedValue = Asn1Integer(0)
    ),
    IntegerVector(
        name = "reject-overlong-zero-two-leading-00",
        hex = "02 03 00 00 00",
        shouldAccept = false,
        note = "Redundant positive sign-extension octets.",
        expectedValue = Asn1Integer(0)
    ),
    IntegerVector(
        name = "reject-overlong-positive-one",
        hex = "02 02 00 01",
        shouldAccept = false,
        note = "+1 does not need leading 00.",
        expectedValue = Asn1Integer(1)
    ),
    IntegerVector(
        name = "reject-overlong-positive-127",
        hex = "02 02 00 7F",
        shouldAccept = false,
        note = "+127 does not need leading 00 because sign bit is clear.",
        expectedValue = Asn1Integer(127)
    ),
    IntegerVector(
        name = "reject-overlong-positive-128-extra-00",
        hex = "02 03 00 00 80",
        shouldAccept = false,
        note = "+128 needs exactly one leading 00, not two.",
        expectedValue = Asn1Integer(128)
    ),
    IntegerVector(
        name = "reject-overlong-positive-256-leading-00",
        hex = "02 03 00 01 00",
        shouldAccept = false,
        note = "+256 does not need leading 00 because 01 has sign bit clear.",
        expectedValue = Asn1Integer(256)
    ),

    IntegerVector(
        name = "reject-overlong-negative-one",
        hex = "02 02 FF FF",
        shouldAccept = false,
        note = "-1 must be encoded as single FF.",
        expectedValue = Asn1Integer(-1)
    ),
    IntegerVector(
        name = "reject-overlong-negative-128",
        hex = "02 02 FF 80",
        shouldAccept = false,
        note = "-128 does not need leading FF.",
        expectedValue = Asn1Integer(-128)
    ),
    IntegerVector(
        name = "reject-overlong-negative-129-extra-FF",
        hex = "02 03 FF FF 7F",
        shouldAccept = false,
        note = "-129 needs exactly one leading FF, not two.",
        expectedValue = Asn1Integer(-129)
    ),
    IntegerVector(
        name = "reject-overlong-negative-256-leading-FF",
        hex = "02 03 FF FF 00",
        shouldAccept = false,
        note = "-256 does not need two leading FF octets.",
        expectedValue = Asn1Integer(-256)
    )
)

val FocusedINTEGERTests by matrixSuite {

    data("integer", nonMinimal + minimal, nameFn = { it.name }) test { (_, hex, shouldAccept, note, expected) ->
        withClue(note) {
            if (shouldAccept)
                Asn1Integer.parseFromDerHexString(hex).toDerHexString() shouldBe hex.replace(" ", "")
            else {
                shouldThrow<Asn1Exception> {
                    Asn1Integer.parseFromDerHexString(hex)
                }
                    val decoded =
                        Asn1Integer.fromTwosComplement((Asn1Element.parseFromDerHexString(hex) as Asn1Primitive).content, lenient = true)

                    withClue("Manual decoding is lenient as escape hatch") {
                        decoded shouldBe expected
                    }
                    withClue("Round-trip mormalizes") {
                        Asn1Integer.decodeFromTlv(decoded.encodeToTlv()) shouldBe expected
                    }
            }
        }
    }

}

data class IntegerVector(
    val name: String,
    val hex: String,
    val shouldAccept: Boolean,
    val note: String,
    val expectedValue: Asn1Integer,
)
