// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

/*
 * Time and PEM findings: accepted input that does not survive a round trip.
 *
 * Each of these accepts something it should reject and then emits something different from what it read. That breaks
 * any verifier that recomputes bytes to check a signature over them, and in the PEM cases it lets wire-controlled
 * text place its own BEGIN/END fences into a document another parser will read.
 *
 * Each case asserts the CORRECT (post-fix) behaviour, so it FAILS while the defect is present. Where the original
 * reproducer had an A/B shape ("this spelling works, that spelling breaks"), the working leg is kept as an in-test
 * control marked `Control (A)`, so a failure cannot be blamed on a broken fixture. Test names are the finding ids
 * under `findings/<harness>/submitted_humanreadable`.
 */

package at.asitplus.awesn1

import at.asitplus.awesn1.encoding.parse
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json

@OptIn(ExperimentalStdlibApi::class)
val TimeAndPemFindings by matrixSuite {
    "UTCTime terminator" - {
        /*
         * utctime_lowercase_z_roundtrip_normalization
         *
         * BUG: compatibility decoding accepts a lowercase-'z' UTCTime but discards that spelling,
         * silently canonicalising it to 'Z' on re-encode. GeneralizedTime remains strict.
         *
         * TRIGGER: UTCTime content "260102030405z" must round-trip byte-exactly. Programmatic
         * construction remains canonical and GeneralizedTime rejects lowercase 'z'.
         */
        "utctime_lowercase_z_roundtrip_normalization" {
            val lowercase = Asn1Primitive(
                Asn1Element.Tag(0x17uL, constructed = false, tagClass = TagClass.UNIVERSAL),
                "260102030405z".encodeToByteArray(),
            )

            // Control (A): GENERALIZED TIME enforces the uppercase terminator.
            shouldThrow<Asn1Exception> {
                Asn1Time.decodeFromTlv(
                    Asn1Primitive(
                        Asn1Element.Tag(0x18uL, constructed = false, tagClass = TagClass.UNIVERSAL),
                        "20250101000000z".encodeToByteArray(),
                    )
                )
            }

            // Fault (B): compatibility input is accepted without rewriting its wire form.
            Asn1Time.decodeFromTlv(lowercase).encodeToTlv().content.decodeToString() shouldBe "260102030405z"

            // Programmatic encoding always emits the canonical DER terminator.
            Asn1Time.SecondsCapped(
                kotlin.time.Instant.parse("2026-01-02T03:04:05Z"),
                Asn1Time.Format.UTC,
            ).encodeToTlv().content.decodeToString() shouldBe "260102030405Z"
        }

        /*
         * utctime_lowercase_zulu_roundtrip_break
         *
         * BUG: the same missing terminator check seen through the full parse -> decode -> encode
         * path: the re-encoded TLV ends in 0x5A where the input ended in 0x7A, so a verifier that
         * recomputes TBS bytes checks a signature over bytes that are not the ones signed.
         *
         * TRIGGER: the TLV 17 0D "250302131530z"; compatibility decoding must preserve it byte-exactly.
         */
        "utctime_lowercase_zulu_roundtrip_break" {
            val tlv = byteArrayOf(0x17, 13) + "250302131530z".encodeToByteArray()
            val parsed = Asn1Element.parse(tlv) as Asn1Primitive
            val reEncoded = runCatching { Asn1Time.decodeFromTlv(parsed).encodeToTlv().derEncoded }
            if (reEncoded.isSuccess) reEncoded.getOrThrow().toHexString() shouldBe tlv.toHexString()
        }
    }

    "time subtype fidelity" - {
        /*
         * kxs_time_fractional_whole_second_subtype_flip_v2
         *
         * BUG: Asn1TimeSerializer.serialize emits only `value.instant.toString()`, dropping both
         * the Asn1Time subtype and Fractional.fractionalSeconds; deserialize then rebuilds via
         * Asn1Time(Instant) which picks SecondsCapped whenever the nanosecond field is zero. A
         * Fractional with an all-zero fraction therefore silently changes type, stops being
         * equal to itself and re-encodes to different DER — fatal for TBS byte comparison.
         *
         * TRIGGER: the GENERALIZED TIME string "20200101000000.000Z".
         */
        "kxs_time_fractional_whole_second_subtype_flip_v2" {
            val original = Asn1Time("20200101000000.000Z")
            val roundTripped = Json.decodeFromString(
                Asn1Time.Companion,
                Json.encodeToString(Asn1Time.Companion, original),
            )
            roundTripped.encodeToTlv().derEncoded.toHexString() shouldBe original.encodeToTlv().derEncoded.toHexString()
        }
    }

    "PEM fence injection" - {
        /*
         * pem_encode_linebreak_injection
         *
         * BUG: neither PemBlock.init nor encodeToPem() rejects line breaks in the label or in
         * PemHeader name/value, so an injected "-----END ...-----" line terminates the block
         * early. The emitted PEM re-parses as a block with an EMPTY payload — 30 bytes encoded,
         * 0 recovered, no exception anywhere.
         *
         * TRIGGER: PemHeader("Comment", "hi\n-----END CERTIFICATE-----").
         * Control: a clean header round-trips all 30 bytes.
         */
        "pem_encode_linebreak_injection" {
            val payload = ByteArray(30) { it.toByte() }

            // Control (A): a clean block round-trips.
            PemBlock.decodeAllFromPem(
                PemBlock("CERTIFICATE", listOf(PemHeader("Comment", "clean")), payload).encodeToPem()
            ).single().payload.size shouldBe 30

            // Fault (B): an injected END fence must be rejected at construction time.
            shouldThrow<IllegalArgumentException> {
                PemBlock("CERTIFICATE", listOf(PemHeader("Comment", "hi\n-----END CERTIFICATE-----")), payload)
            }
        }

        /*
         * pem_label_newline_fence_injection_roundtrip_break
         *
         * BUG: the label variant of the same hole — PemBlock's init only checks isNotBlank(), and
         * encodeToPem() interpolates the label unescaped into both fences. A label carrying a
         * complete fence emits attacker BEGIN/END lines and the encode -> parse round trip breaks.
         * Whitespace padding is a milder instance: " CERTIFICATE " re-parses as "CERTIFICATE",
         * so the round trip is not the identity.
         *
         * TRIGGER: label "CERT\n-----END CERT-----\n-----BEGIN SMUGGLED".
         */
        "pem_label_newline_fence_injection_roundtrip_break" {
            shouldThrow<IllegalArgumentException> {
                PemBlock("CERT\n-----END CERT-----\n-----BEGIN SMUGGLED", payload = byteArrayOf(1, 2, 3))
            }
        }
    }
}
