// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(ExperimentalStdlibApi::class)

package at.asitplus.awesn1

import at.asitplus.awesn1.encoding.parse
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.Json
import kotlin.time.Instant

// Suite names preserve the original finding identifiers.
val utctime_lowercase_z_roundtrip_normalization by matrixSuite {
    "GeneralizedTime rejects a lowercase terminator" {
        shouldThrow<Asn1Exception> {
            Asn1Time.decodeFromTlv(
                Asn1Primitive(Asn1Element.Tag.TIME_GENERALIZED, "20250101000000z".encodeToByteArray())
            )
        }
    }

    "Compatibility UTCTime decoding preserves a lowercase terminator" {
        val lowercase = Asn1Primitive(Asn1Element.Tag.TIME_UTC, "260102030405z".encodeToByteArray())
        Asn1Time.decodeFromTlv(lowercase).encodeToTlv().content.decodeToString() shouldBe "260102030405z"
    }

    "Programmatic UTCTime encoding uses the canonical uppercase terminator" {
        Asn1Time.SecondsCapped(
            Instant.parse("2026-01-02T03:04:05Z"),
            Asn1Time.Format.UTC,
        ).encodeToTlv().content.decodeToString() shouldBe "260102030405Z"
    }
}

val utctime_lowercase_zulu_roundtrip_break by matrixSuite {
    "Parsing, decoding, and re-encoding a lowercase UTCTime preserves every byte" {
        val tlv = byteArrayOf(0x17, 13) + "250302131530z".encodeToByteArray()
        val parsed = Asn1Element.parse(tlv) as Asn1Primitive
        Asn1Time.decodeFromTlv(parsed).encodeToTlv().derEncoded.toHexString() shouldBe tlv.toHexString()
    }
}

val kxs_time_fractional_whole_second_subtype_flip_v2 by matrixSuite {
    "JSON round-tripping retains a whole-second Fractional value and its zero digits" {
        val original = Asn1Time("20200101000000.000Z")
        val roundTripped = Json.decodeFromString(
            Asn1Time.Companion,
            Json.encodeToString(Asn1Time.Companion, original),
        )
        roundTripped.shouldBeInstanceOf<Asn1Time.Fractional>().fractionalSeconds shouldBe "000"
        roundTripped.encodeToTlv().derEncoded.toHexString() shouldBe original.encodeToTlv().derEncoded.toHexString()
    }

    "JSON round-tripping preserves fractional precision beyond nanoseconds" {
        val original = Asn1Time("20200101000000.1234567890123456789Z")
        val roundTripped = Json.decodeFromString(
            Asn1Time.Companion,
            Json.encodeToString(Asn1Time.Companion, original),
        )
        roundTripped.encodeToTlv().derEncoded.toHexString() shouldBe original.encodeToTlv().derEncoded.toHexString()
    }

    "JSON round-tripping preserves GeneralizedTime within the UTCTime date range" {
        val original = Asn1Time("20200101000000Z")
        val roundTripped = Json.decodeFromString(
            Asn1Time.Companion,
            Json.encodeToString(Asn1Time.Companion, original),
        )
        roundTripped.format shouldBe Asn1Time.Format.GENERALIZED
        roundTripped.encodeToTlv().derEncoded.toHexString() shouldBe original.encodeToTlv().derEncoded.toHexString()
    }

    "JSON retains UTCTime's format and lowercase compatibility terminator" {
        val json = "\"260102030405z\""
        val decoded = Json.decodeFromString(Asn1Time.Companion, json)
        decoded.format shouldBe Asn1Time.Format.UTC
        decoded.encodeToTlv().content.decodeToString() shouldBe "260102030405z"
        Json.encodeToString(Asn1Time.Companion, decoded) shouldBe json
    }

    "JSON decoding still accepts legacy ISO-8601 timestamps" {
        Json.decodeFromString(Asn1Time.Companion, "\"2026-01-02T03:04:05Z\"").instant shouldBe
                Instant.parse("2026-01-02T03:04:05Z")
    }
}
