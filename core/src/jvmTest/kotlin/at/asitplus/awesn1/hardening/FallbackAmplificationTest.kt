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
 * The amplification numbers here are the ones quoted in `BoundedFallbackSerializer`'s KDoc and in
 * `docs/docs/hardening.md`. They are asserted as loose bands rather than exact values, so they survive JIT and JVM
 * differences but still fail if a decode grows a new copy of its input.
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
        "OBJECT IDENTIFIER is bounded well below the shared default" {
            ObjectIdentifierStringSerializer.decodingLimit shouldBe ObjectIdentifier.MAX_OID_STRING_CHARS
            (ObjectIdentifierStringSerializer.decodingLimit < DEFAULT_FALLBACK_DECODING_LIMIT) shouldBe true

            // within the limit: still an ordinary OID
            Json.decodeFromString(ObjectIdentifierStringSerializer, json("1.2.840.113549.1.1.11"))
                .toString() shouldBe "1.2.840.113549.1.1.11"

            // past it: rejected, and rejected before a single VarUInt is built
            shouldThrow<SerializationException> {
                Json.decodeFromString(
                    ObjectIdentifierStringSerializer,
                    json(oidString(ObjectIdentifier.MAX_OID_STRING_CHARS + 2)),
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
         * Why OBJECT IDENTIFIER gets a 4 KiB default while hex INTEGER gets 384 MiB. One VarUInt is retained per
         * node, and a dotted string declares a node every two characters; a hex INTEGER is half its input, once.
         * Measured on JDK 17/M3: OID ~224x transient and ~22x retained, hex ~0.5x both.
         */
        "an OID string costs orders of magnitude more per character than a hex INTEGER" {
            val chars = 128 * 1024
            val oid = oidString(chars)
            val hex = "f".repeat(chars)

            // warm up so class init and JIT do not land on whichever runs first
            repeat(2) {
                ObjectIdentifier(oid)
                Asn1Integer.fromHexString(hex)
            }

            var oidResult: ObjectIdentifier? = null
            val oidCost = allocatedBytes { oidResult = ObjectIdentifier(oid) }
            oidResult!!.nodes.size shouldBe (chars - 3) / 2 + 2

            var hexResult: Asn1Integer? = null
            val hexCost = allocatedBytes { hexResult = Asn1Integer.fromHexString(hex) }
            hexResult shouldNotBe null

            (hexCost < chars.toLong()) shouldBe true          // ~0.5x
            (oidCost > hexCost * 20) shouldBe true            // ~224x vs ~0.5x, asserted at 20x apart
            (oidCost < chars.toLong() * 400) shouldBe true    // ratchet: fails if the decode grows another copy
        }
    }
}
