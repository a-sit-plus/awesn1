// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

/*
 * The fallback serializers exist so ASN.1 types can travel through formats that have no ASN.1 representation.
 * That contract is only observable through such a format, so these tests use JSON — a test-only dependency of
 * :core, never a production one.
 *
 * The mirror of this file is in :kxs, where the same serializers must be *rejected* by the DER format.
 */

package at.asitplus.awesn1

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json
import kotlin.time.Instant

private inline fun <reified T> roundTrip(
    serializer: kotlinx.serialization.KSerializer<T>,
    value: T,
    expectedJson: String,
) {
    val encoded = Json.encodeToString(serializer, value)
    encoded shouldBe expectedJson
    Json.decodeFromString(serializer, encoded) shouldBe value
}

val FallbackSerializerJsonTest by matrixSuite {

    "Asn1Integer hex fallback round-trips through JSON" {
        val value = Asn1Integer.fromDecimalString("123456789012345678901234567890")
        val encoded = Json.encodeToString(Asn1IntegerHexStringSerializer, value)
        Json.decodeFromString(Asn1IntegerHexStringSerializer, encoded) shouldBe value
    }

    "Asn1Integer decimal fallback round-trips through JSON" {
        roundTrip(Asn1IntegerDecimalStringSerializer, Asn1Integer.fromDecimalString("-42"), "\"-42\"")
    }

    "Asn1Integer's registered fallback is used when the format is not DER" {
        // Asn1Integer.Companion delegates to its hex fallback for non-DER formats.
        val value = Asn1Integer.fromDecimalString("255")
        val encoded = Json.encodeToString(Asn1Integer.serializer(), value)
        Json.decodeFromString(Asn1Integer.serializer(), encoded) shouldBe value
    }

    "ObjectIdentifier fallback round-trips through JSON" {
        roundTrip(ObjectIdentifierStringSerializer, ObjectIdentifier("1.2.840.113549"), "\"1.2.840.113549\"")
        val viaCompanion = Json.encodeToString(ObjectIdentifier.serializer(), ObjectIdentifier("2.5.4.3"))
        Json.decodeFromString(ObjectIdentifier.serializer(), viaCompanion) shouldBe ObjectIdentifier("2.5.4.3")
    }

    "Asn1Real fallback round-trips through JSON" {
        val value = Asn1Real(1.5)
        Json.decodeFromString(Asn1RealStringSerializer, Json.encodeToString(Asn1RealStringSerializer, value)) shouldBe
                value
        Json.decodeFromString(Asn1Real.serializer(), Json.encodeToString(Asn1Real.serializer(), value)) shouldBe value
    }

    "Asn1Time round-trips through JSON via its registered fallback" {
        val value = Asn1Time(Instant.fromEpochSeconds(1_600_000_000))
        Json.decodeFromString(Asn1Time.serializer(), Json.encodeToString(Asn1Time.serializer(), value)) shouldBe value
    }

    "Asn1BitString round-trips through JSON via its registered fallback" {
        val value = Asn1BitString(byteArrayOf(0x0F, 0x71.toByte()))
        Json.decodeFromString(Asn1BitString.serializer(), Json.encodeToString(Asn1BitString.serializer(), value)) shouldBe
                value
    }

    "Asn1String round-trips through JSON and keeps its subtype" {
        val utf8 = Asn1String.UTF8("héllo")
        Json.decodeFromString(Asn1String.serializer(), Json.encodeToString(Asn1String.serializer(), utf8)) shouldBe utf8

        val printable = Asn1String.Printable("AB")
        Json.decodeFromString(
            Asn1String.Printable.serializer(),
            Json.encodeToString(Asn1String.Printable.serializer(), printable),
        ) shouldBe printable
    }

    "Asn1Element trees round-trip through JSON as Base64 DER" {
        val element: Asn1Element = Asn1Primitive(Asn1Element.Tag.INT, byteArrayOf(0x07))
        val encoded = Json.encodeToString(Asn1ElementFallbackBase64Serializer, element)
        Json.decodeFromString(Asn1ElementFallbackBase64Serializer, encoded) shouldBe element
    }
}
