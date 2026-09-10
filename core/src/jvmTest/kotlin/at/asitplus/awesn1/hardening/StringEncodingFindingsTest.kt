// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

/*
 * String-encoding findings: content silently misread or rewritten.
 *
 * X.690 gives BMPString, UniversalString and TeletexString their own encodings, but the decoders read everything as
 * UTF-8. The result is not an error but a wrong value, and because equality compares the lossy decoded string rather
 * than the raw bytes, distinct wire values can compare equal while re-encoding to different bytes.
 *
 * Each case asserts the CORRECT (post-fix) behaviour, so it FAILS while the defect is present. Where the original
 * reproducer had an A/B shape ("this spelling works, that spelling breaks"), the working leg is kept as an in-test
 * control marked `Control (A)`, so a failure cannot be blamed on a broken fixture. Test names are the finding ids
 * under `findings/<harness>/submitted_humanreadable`.
 */

package at.asitplus.awesn1

import at.asitplus.awesn1.encoding.decodeToBmpString
import at.asitplus.awesn1.encoding.parse
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json

@OptIn(ExperimentalStdlibApi::class)
val StringEncodingFindings by matrixSuite {
    "wide string types decoded as UTF-8" - {
        /*
         * bmp_universal_string_utf8_content
         *
         * BUG: Asn1String.BMP / .Universal store `value.encodeToByteArray()` — i.e. UTF-8 — where
         * X.690 mandates UCS-2BE / UCS-4, and neither the `value` getter nor decodeToBmpString
         * transcodes back. Encoding is therefore silently non-conformant (and can even produce an
         * ODD-length BMPString), and conformant peer input decodes to mojibake.
         *
         * TRIGGER: BMP("A") must encode as 1E 02 00 41, and a conformant UCS-2BE "Müller" must
         * decode back to "Müller".
         */
        "bmp_universal_string_utf8_content" {
            // Fault (B1): encoding must be UCS-2BE, not UTF-8 (and never odd-length).
            Asn1String.BMP("A").encodeToTlv().derEncoded.toHexString() shouldBe "1e020041"

            // Fault (B2): conformant UCS-2BE input must decode to the real string.
            val conformant = "1e0c004d00fc006c006c00650072".hexToByteArray()
            (Asn1Element.parse(conformant) as Asn1Primitive).decodeToBmpString().value shouldBe "Müller"
        }

        /*
         * string_decode_value_utf8_misdecode
         *
         * BUG: String.decodeFromAsn1ContentBytes applies UTF-8 unconditionally, so BMPString /
         * UniversalString content is misread, and Asn1String.equals/hashCode compare the resulting
         * LOSSY value rather than rawValue — so two DER strings that encode differently compare
         * equal and hash equal, defeating identity and duplicate checks.
         *
         * TRIGGER: BMPString 'Ä' (00 C4) vs 'Å' (00 C5).
         */
        "string_decode_value_utf8_misdecode" {
            val a = Asn1Primitive(Asn1Element.Tag.STRING_BMP, "00c4".hexToByteArray())
            val b = Asn1Primitive(Asn1Element.Tag.STRING_BMP, "00c5".hexToByteArray())

            // Fault (B1): a conformant UCS-2 'A' must decode to "A".
            Asn1Primitive(Asn1Element.Tag.STRING_BMP, "0041".hexToByteArray())
                .decodeToBmpString().value shouldBe "A"

            // Fault (B2): distinct DER strings must not compare equal.
            a.decodeToBmpString() shouldNotBe b.decodeToBmpString()
        }
    }

    "silent content rewriting" - {
        /*
         * implicit_utf8_decode_silently_rewrites_bytes
         *
         * BUG: the implicit-tag fallback in Asn1Utf8StringSerializer.decodeFromTlv builds the
         * Asn1String from a decoded Kotlin String instead of using the byte-preserving ByteArray
         * constructor. Malformed UTF-8 is therefore accepted and silently rewritten to U+FFFD, so
         * the decode is lossy AND non-injective: 0x80 and 0xFF become equal objects.
         *
         * TRIGGER: an implicitly tagged [0] primitive whose content is 41 C0 80 42.
         */
        "implicit_utf8_decode_silently_rewrites_bytes" {
            val tag = Asn1Element.Tag(0uL, constructed = false, tagClass = TagClass.CONTEXT_SPECIFIC)
            val malformed = byteArrayOf(0x41, 0xC0.toByte(), 0x80.toByte(), 0x42)

            // A concrete UTF8String decoder is strict even for implicit content.
            shouldThrow<Asn1Exception> {
                Asn1Utf8StringSerializer.decodeFromTlv(Asn1Primitive(tag, malformed), null)
            }
            shouldThrow<Asn1Exception> {
                Asn1Utf8StringSerializer.decodeFromTlv(Asn1Primitive(tag, byteArrayOf(0x80.toByte())), null)
            }
        }

        /*
         * utf8_serializer_lone_surrogate_silent_mutation
         *
         * BUG: Asn1String.UTF8's String constructor derives isValid by comparing
         * value.encodeToByteArray() against a rawValue built from the SAME call — a tautology, so
         * the documented Asn1Exception path is unreachable. A lone surrogate is silently replaced
         * by '?' (0x3F), and Asn1Utf8StringSerializer's JSON branch therefore breaks
         * deserialize -> serialize identity.
         *
         * TRIGGER: the JSON string "a\ud800b". Control: "héllo" round-trips exactly.
         */
        "utf8_serializer_lone_surrogate_silent_mutation" {
            // Control (A): ordinary text round-trips.
            Json.encodeToString(
                Asn1Utf8StringSerializer,
                Json.decodeFromString(Asn1Utf8StringSerializer, "\"héllo\""),
            ) shouldBe "\"héllo\""

            // Fault (B): a lone surrogate is silently rewritten to '?' instead of being rejected.
            // The JSON path surfaces the rejection as SerializationException, per the format
            // contract in StringFallbackSerializer; the Asn1Exception is retained as its cause.
            val thrown = shouldThrow<SerializationException> {
                Json.decodeFromString(Asn1Utf8StringSerializer, "\"a\\ud800b\"")
            }
            thrown.cause.shouldBeInstanceOf<Asn1Exception>()
        }
    }

    "tag gates" - {
        /*
         * string_implicit_tag_gate_fails_open
         *
         * BUG: decodeImplicitlyTaggedAsn1StringSubtype only enforces the declared tag when
         * assertTag is non-null AND differs from the semantic tag, and its implicit-content
         * fallback is unguarded. Passing the string's OWN universal tag as the assertion therefore
         * disables the check entirely: an OCTET STRING is accepted as a UTF8String and silently
         * re-tagged, so the accepted input does not re-encode to itself.
         *
         * TRIGGER: an OCTET STRING primitive asserted against Tag.STRING_UTF8.
         * Control: a foreign assertTag (PRINTABLE) does throw, so the gate exists.
         */
        "string_implicit_tag_gate_fails_open" {
            val octetString = Asn1Primitive(Asn1Element.Tag.OCTET_STRING, "admin".encodeToByteArray())

            // Control (A): a foreign assertion is enforced.
            shouldThrow<Asn1Exception> {
                Asn1Utf8StringSerializer.decodeFromTlv(octetString, Asn1Element.Tag.STRING_PRINTABLE)
            }

            // Fault (B): asserting the string's own universal tag disables the gate.
            shouldThrow<Asn1Exception> {
                Asn1Utf8StringSerializer.decodeFromTlv(octetString, Asn1Element.Tag.STRING_UTF8)
            }
        }
    }
}
