// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(ExperimentalStdlibApi::class, kotlin.io.encoding.ExperimentalEncodingApi::class)

/*
 * The non-DER fallback serializers and the limits they carry.
 *
 * Under a generic format (JSON, CBOR, ...) awesn1's types decode through fallback serializers rather than through
 * the DER parser, so `DER { maxInputLength }` does not reach them. Each of those serializers carries a character
 * limit instead; the defaults differ by two orders of magnitude because the decodes do, and this suite pins both
 * halves of that: the limits fire, and the cost model behind them still holds.
 *
 * The measured figures live in `docs/docs/hardening.md#fallback-decoding-limits` and nowhere else — this suite
 * asserts the *cost model* those figures describe, as loose bands rather than exact values, so it survives JIT and
 * JVM differences but still fails if a decode grows a new copy of its input. Note that a band this wide will not
 * notice a figure in that table going stale: re-measure when the decode changes.
 */

package at.asitplus.awesn1

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json

/** JSON string literal holding [content]. */
private fun json(content: String) = "\"" + content + "\""

/** A dotted OID string of [chars] characters: `1.2.1.1.1...`, i.e. one node per two characters. */
private fun oidString(chars: Int) = "1.2" + ".1".repeat((chars - 3) / 2)

val FallbackAmplification by matrixSuite {

    "per-serializer limits" - {
        /*
         * Each of these decodes is reachable from any non-DER format, and each is bounded by a limit of its own
         * rather than by the shared default, because its cost per input character differs by orders of magnitude.
         */
        /*
         * OBJECT IDENTIFIER tracks the shared default; what bounds it independently is the per-node cap, which
         * keeps the quadratic big-integer conversion within reach however short the whole string is.
         */
        "OBJECT IDENTIFIER tracks the shared default, but still caps a single node" {
            ObjectIdentifierStringSerializer.decodingLimit shouldBe DEFAULT_FALLBACK_DECODING_LIMIT

            Json.decodeFromString(ObjectIdentifierStringSerializer, json("1.2.840.113549.1.1.11"))
                .toString() shouldBe "1.2.840.113549.1.1.11"

            // one absurdly long arc is rejected regardless of how short the whole string is
            shouldThrow<SerializationException> {
                Json.decodeFromString(
                    ObjectIdentifierStringSerializer,
                    json("1.2." + "9".repeat(ObjectIdentifier.MAX_SUBIDENTIFIER_CHARS + 1)),
                )
            }
        }

        "timestamps are bounded to a timestamp's length" {
            Json.decodeFromString(Asn1TimeSerializer, json("2026-09-08T05:36:00Z"))
                .instant.toString() shouldBe "2026-09-08T05:36:00Z"

            shouldThrow<SerializationException> {
                Json.decodeFromString(Asn1TimeSerializer, json("9".repeat(1024)))
            }
        }

        "REAL is bounded below the shared default" {
            (Asn1RealStringSerializer.decodingLimit < DEFAULT_FALLBACK_DECODING_LIMIT) shouldBe true

            Json.decodeFromString(Asn1RealStringSerializer, json("1 * 2^1")) shouldBe Asn1Real(2.0)

            shouldThrow<SerializationException> {
                Json.decodeFromString(
                    Asn1RealStringSerializer,
                    json("f".repeat(Asn1RealStringSerializer.decodingLimit) + " * 2^1"),
                )
            }
        }

        /*
         * The registered fallback for INTEGER is the hex one, and that is deliberate: hex conversion is linear,
         * decimal conversion is quadratic in the digit count. So the cheap form is the default and the expensive
         * form is opt-in with a tight limit — the opposite assignment would be the dangerous one.
         */
        "INTEGER: the quadratic decimal form is the tightly bounded one" {
            (Asn1IntegerDecimalStringSerializer.decodingLimit < Asn1IntegerHexStringSerializer.decodingLimit)
                .shouldBe(true)
            Asn1IntegerHexStringSerializer.decodingLimit shouldBe DEFAULT_FALLBACK_DECODING_LIMIT

            shouldThrow<SerializationException> {
                Json.decodeFromString(
                    Asn1IntegerDecimalStringSerializer,
                    json("9".repeat(Asn1IntegerDecimalStringSerializer.decodingLimit + 1)),
                )
            }
        }
    }

    "the shared default" - {
        /*
         * `defaultDecodingLimit` is a process-global `var`, so this suite only reads it; mutating it would race
         * every other test decoding a fallback value concurrently. Enforcement of a changed default is covered in
         * `ResourceExhaustionFindingsTest`, which owns the one place that writes it.
         */
        "serializers whose decode is cheap track it rather than carrying a limit of their own" {
            Asn1IntegerHexStringSerializer.decodingLimit shouldBe BoundedFallbackSerializer.defaultDecodingLimit
            Asn1Utf8StringSerializer.decodingLimit shouldBe BoundedFallbackSerializer.defaultDecodingLimit
            Asn1ElementFallbackBase64Serializer.decodingLimit shouldBe BoundedFallbackSerializer.defaultDecodingLimit
        }

        "bounded() pins a limit for one call site without touching the singleton" {
            val tight = ObjectIdentifierStringSerializer.bounded(4)
            shouldThrow<SerializationException> { Json.decodeFromString(tight, json("1.2.840.113549")) }

            // the singleton is unaffected
            Json.decodeFromString(ObjectIdentifierStringSerializer, json("1.2.840.113549"))
                .toString() shouldBe "1.2.840.113549"
        }
    }

    "amplification bands" - {
        /*
         * A hex INTEGER is half its input, once — the cheapest decode in the family, and the reason it sits on the
         * shared default rather than carrying a limit of its own.
         *
         * See `docs/docs/hardening.md#fallback-decoding-limits` for the measured figures.
         */
        "a hex INTEGER stays half its input" {
            val hex = "f".repeat(128 * 1024)
            repeat(3) { Asn1Integer.fromHexString(hex) }
            var parsed: Asn1Integer? = null
            val cost = allocatedBytes { parsed = Asn1Integer.fromHexString(hex) }
            parsed shouldNotBe null
            (cost < (128 * 1024).toLong()) shouldBe true
        }
    }
}
