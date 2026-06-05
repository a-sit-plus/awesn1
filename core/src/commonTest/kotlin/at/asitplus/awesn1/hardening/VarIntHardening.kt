package at.asitplus.awesn1.at.asitplus.awesn1.hardening


import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldStartWith

private data class HighTagVarIntSample(
    val name: String,
    val hex: String,
    val tagNumberOctets: Int,
    val note: String,
    val expected: ULong? = null
)


val VarUntHardening by matrixSuite(
    execution = ExecutionMode.Sequential,
) {
    data(
        name = "hostile high-tag-number varints",
        values = listOf(
            HighTagVarIntSample(
                name = "eleven-octet-terminated-varint-minimal-shape",
                hex = "1F 81 80 80 80 80 80 80 80 80 80 00 00",
                tagNumberOctets = 11,
                note = "A ULong-backed ASN.1 tag-number decoder should never need 11 base-128 octets."
            ),
            HighTagVarIntSample(
                name = "twenty-octet-terminated-varint",
                hex = "1F " + ("81 ".repeat(19)) + "00 00",
                tagNumberOctets = 20,
                note = "Long enough to make the current accumulator wrap repeatedly before the existing guard fires."
            ),
            HighTagVarIntSample(
                name = "hundred-octet-terminated-varint",
                hex = "1F " + ("81 ".repeat(99)) + "00 00",
                tagNumberOctets = 100,
                note = "Below the current broken 586-ish threshold for bits=64, but far above the correct 10-octet bound."
            )
        ),
        nameFn = { _, value -> "${value.name} (${value.tagNumberOctets} tag-number octets)" },
    ) test { vector ->
        /*
         * Breakpoint inside decodeAsn1VarInt(bits) revealed nonsensical guard:
         *
         *   if (++offset > ceil((bits * 8).toFloat() * 8f / 7f))
         *
         * For bits = 64:
         *   current threshold = 586
         *   correct threshold = 10
         * Should have been *8 … /8 which cancels out
         */
        shouldThrow<Asn1Exception> {
            Asn1Element.parseFromDerHexString(vector.hex)
        }.message.shouldStartWith("Number too Large do decode into")
    }

    data(
        name = "overshoot limit",
        values = listOf(
            HighTagVarIntSample(
                name = "ten-octet-terminated-varint-boundary",
                hex = "1F 82 80 80 80 80 80 80 80 80 00 00",
                tagNumberOctets = 10,
                note = "Does not fit ULong: 2^64. Should trip bitLength overflow."
            ),
            HighTagVarIntSample(
                name = "eleven-octet-terminated-varint-over-boundary",
                hex = "1F 81 80 80 80 80 80 80 80 80 80 00 00",
                tagNumberOctets = 11,
                note = "One octet beyond the maximum possible ULong base-128 length."
            )
        ),
        nameFn = { _, value -> "${value.name} (${value.tagNumberOctets} tag-number octets)" }
    ) test { vector ->
        shouldThrow<Asn1Exception> {
            Asn1Element.parseFromDerHexString(vector.hex)
        }
    }
    data(
        name = "within limit",
        values = listOf(
            HighTagVarIntSample(
                name = "ten-octet-fits-2-to-63",
                hex = "1F 81 80 80 80 80 80 80 80 80 00 00",
                tagNumberOctets = 10,
                note = "Fits ULong: 2^63. Should not fail because of varint width.",
                expected = 1UL shl 63
            ),
            HighTagVarIntSample(
                name = "ten-octet-fits-ulong-max",
                hex = "1F 81 FF FF FF FF FF FF FF FF 7F 00",
                tagNumberOctets = 10,
                note = "Fits ULong.MAX_VALUE. May later fail for policy reasons, but not varint overflow.",
                expected = ULong.MAX_VALUE
            )
        ),
        nameFn = { _, value -> "${value.name} (${value.tagNumberOctets} tag-number octets)" }
    ) test { vector -> Asn1Element.parseFromDerHexString(vector.hex).tag.tagValue shouldBe vector.expected }
}