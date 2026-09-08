// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

/*
 * Exception-contract findings for the non-DER fallback serializers.
 *
 * kotlinx.serialization decoders owe their callers a `SerializationException`. These fallbacks used to let whatever
 * the underlying constructor threw escape instead, and for awesn1 that is worse than a contract violation:
 * `Asn1Exception` extends `Throwable` directly, not `Exception`, so a host's `catch (e: Exception)` around
 * `decodeFromString` did not catch a malformed value at all.
 *
 * All five cases are one defect with five entry points, and they are fixed in one place —
 * `BoundedFallbackSerializer.deserializeBounded` wraps `decodeBounded` in `runWrappingAs(::SerializationException)`.
 * Each case asserts the CORRECT (post-fix) behaviour, so it FAILS while the defect is present. Test names are the
 * finding ids under `findings/tensorix/submitted_humanreadable`.
 */

package at.asitplus.awesn1

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json

/**
 * Asserts that [block] fails the way a decoder is supposed to fail: a [SerializationException], which is also an
 * [Exception], so an ordinary `catch (e: Exception)` contains it. The original failure must survive as the cause,
 * since that is the part a host needs for diagnostics.
 */
private inline fun shouldFailAsSerializationException(expectCause: Boolean = true, block: () -> Unit) {
    val thrown = shouldThrow<Throwable>(block)
    thrown.shouldBeInstanceOf<SerializationException>()
    (thrown is Exception) shouldBe true
    if (expectCause) (thrown.cause != null) shouldBe true
}

val FallbackExceptionContract by matrixSuite {

    /*
     * oid_string_serializer_leaks_raw_asn1exception
     *
     * BUG (fixed): ObjectIdentifierStringSerializer called ObjectIdentifier(String) with no translation, so every
     * malformed dotted string threw a raw Asn1Exception/Asn1StructuralException — a Throwable, not an Exception.
     *
     * TRIGGER: the finding's five malformed OIDs, covering each rejection path in the constructor.
     */
    "oid_string_serializer_leaks_raw_asn1exception" {
        for (malformed in listOf("1.2." + "9".repeat(200), "1.2.x", "1", "", "5.1.2")) {
            shouldFailAsSerializationException {
                Json.decodeFromString(ObjectIdentifier.serializer(), "\"$malformed\"")
            }
        }

        // Control: a well-formed OID still decodes.
        Json.decodeFromString(ObjectIdentifier.serializer(), "\"1.2.840.113549.1.1.11\"")
            .toString() shouldBe "1.2.840.113549.1.1.11"
    }

    /*
     * b64fallback_deserializer_leaks_asn1exception
     *
     * BUG (fixed): the Base64 element fallback leaked Asn1Exception from the DER parse, and a raw
     * IllegalArgumentException from Base64 decoding of a non-Base64 string.
     *
     * TRIGGER: indefinite length, a truncated TLV, an unsupported long-form length, and malformed Base64.
     */
    "b64fallback_deserializer_leaks_asn1exception" {
        for (payload in listOf("MoA=", "MBU=", "CYEB", "@@not-base64@@")) {
            shouldFailAsSerializationException {
                Json.decodeFromString(Asn1ElementFallbackBase64Serializer, "\"$payload\"")
            }
        }
    }

    /*
     * bitstring_fallback_deserializer_leaks_non_serialization_exceptions
     *
     * BUG (fixed): the "<padding>:<base64>" component form leaked IllegalArgumentException from its own `require`,
     * NumberFormatException from the padding parse, and Asn1Exception from fromRawParts.
     *
     * TRIGGER: the finding's five payloads — bad padding count, no separator, an unparseable padding value,
     * malformed Base64, and a padding count of 8.
     */
    "bitstring_fallback_deserializer_leaks_non_serialization_exceptions" {
        for (payload in listOf("6:IA==", "1", "99999999999999:AAAA", "1:!!!", "8:AAAA")) {
            shouldFailAsSerializationException {
                Json.decodeFromString(Asn1BitString.serializer(), "\"$payload\"")
            }
        }

        // Control: a well-formed bit string still decodes.
        Json.decodeFromString(Asn1BitString.serializer(), "\"0:AAAA\"").bitCarryingBytes.size shouldBe 3
    }

    /*
     * kxs_int_decimal_string_serializer_leaks_raw_asn1exception
     *
     * BUG (fixed): the opt-in decimal INTEGER serializer leaked Asn1Exception for malformed digits, for empty
     * input, and for input past its own decodingLimit.
     *
     * TRIGGER: a non-numeric string, an empty string, and one character past the limit.
     */
    "kxs_int_decimal_string_serializer_leaks_raw_asn1exception" {
        for (malformed in listOf("12x34", "")) {
            shouldFailAsSerializationException {
                Json.decodeFromString(Asn1IntegerDecimalStringSerializer, "\"$malformed\"")
            }
        }

        // over the limit: refused by deserializeBounded itself, so there is no underlying cause to carry
        shouldFailAsSerializationException(expectCause = false) {
            Json.decodeFromString(
                Asn1IntegerDecimalStringSerializer,
                "\"" + "9".repeat(Asn1IntegerDecimalStringSerializer.decodingLimit + 1) + "\"",
            )
        }

        // Control: a decimal INTEGER within the limit still decodes.
        Json.decodeFromString(Asn1IntegerDecimalStringSerializer, "\"255\"").toDecimalString() shouldBe "255"
    }

    /*
     * kxs_time_malformed_string_exception_leak
     *
     * BUG (fixed): Asn1TimeSerializer handed the string straight to Instant.parse, so an InstantFormatException
     * escaped instead of a SerializationException.
     *
     * TRIGGER: a string that is not a timestamp, and one that is shaped like a timestamp but out of range.
     */
    "kxs_time_malformed_string_exception_leak" {
        for (malformed in listOf("not-a-time", "2020-13-99T99:99:99Z")) {
            shouldFailAsSerializationException {
                Json.decodeFromString(Asn1Time.Companion, "\"$malformed\"")
            }
        }

        // Control: a well-formed instant still decodes.
        Json.decodeFromString(Asn1Time.Companion, "\"2026-09-08T05:36:00Z\"")
            .instant.toString() shouldBe "2026-09-08T05:36:00Z"
    }

    /*
     * kxs_int_decimal_string_serializer_leaks_raw_asn1exception (encode half)
     *
     * BUG (fixed): the same leak on the way OUT. Rendering a magnitude past `encodingLimit` threw Asn1Exception
     * straight out of `serialize`, so `catch (e: Exception)` around encodeToString missed it too.
     *
     * TRIGGER: a value one byte past the encoding limit.
     */
    "decimal INTEGER encode failures are SerializationExceptions too" {
        val overCap = Asn1Integer.fromUnsignedByteArray(
            ByteArray(Asn1IntegerDecimalStringSerializer.encodingLimit + 1).also { it[0] = 0x01 }
        )
        shouldFailAsSerializationException {
            Json.encodeToString(Asn1IntegerDecimalStringSerializer, overCap)
        }

        // Control: a value within the limit still encodes.
        Json.encodeToString(Asn1IntegerDecimalStringSerializer, Asn1Integer(255)) shouldBe "\"255\""
    }

    /*
     * kxs_int_decimal_todecimalstring_limit_rejects_accepted_values
     *
     * BUG (fixed): decodingLimit is derived from encodingLimit with ~2.41 chars per byte plus one, which
     * overestimates log10(256) = 2.40824. Strings in the resulting band decoded to magnitudes of up to 32_792
     * bytes — past the 32_768-byte encoding limit — so the serializer accepted values it then refused to render.
     *
     * The character limit is now a pre-filter only; the magnitude is checked on the way in as well, so accepted
     * and re-encodable are the same set. Rejection happens at decode, where a host can act on it, rather than
     * later at encode, where the value is already in its object graph.
     *
     * TRIGGER: the finding's maximal accepted input — decodingLimit nines, which decode to 32_792 bytes.
     */
    "kxs_int_decimal_todecimalstring_limit_rejects_accepted_values" {
        val maximalAccepted = "9".repeat(Asn1IntegerDecimalStringSerializer.decodingLimit)
        shouldFailAsSerializationException {
            Json.decodeFromString(Asn1IntegerDecimalStringSerializer, "\"" + maximalAccepted + "\"")
        }

        // Control (A): the largest magnitude that still round-trips does so, in both directions.
        val atLimit = Asn1Integer.fromUnsignedByteArray(
            ByteArray(Asn1IntegerDecimalStringSerializer.encodingLimit).also { it[0] = 0x01 }
        )
        val json = Json.encodeToString(Asn1IntegerDecimalStringSerializer, atLimit)
        Json.decodeFromString(Asn1IntegerDecimalStringSerializer, json) shouldBe atLimit

        // ...and whatever decodes can be re-encoded, which is the property that was missing.
        val decoded = Json.decodeFromString(Asn1IntegerDecimalStringSerializer, json)
        Json.encodeToString(Asn1IntegerDecimalStringSerializer, decoded) shouldBe json
    }
}
