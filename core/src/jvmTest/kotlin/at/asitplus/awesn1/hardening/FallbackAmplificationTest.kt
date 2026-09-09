// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(ExperimentalStdlibApi::class, kotlin.io.encoding.ExperimentalEncodingApi::class)

package at.asitplus.awesn1

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json

private fun json(content: String) = "\"$content\""

val FallbackAmplification by matrixSuite {
    "serializer-specific limits" - {
        "OBJECT IDENTIFIER caps individual nodes" {
            ObjectIdentifierStringSerializer.decodingLimit shouldBe DEFAULT_FALLBACK_DECODING_LIMIT
            shouldThrow<SerializationException> {
                Json.decodeFromString(
                    ObjectIdentifierStringSerializer,
                    json("1.2." + "9".repeat(ObjectIdentifier.MAX_SUBIDENTIFIER_CHARS + 1)),
                )
            }
        }

        "timestamps and REAL values have tight limits" {
            Json.decodeFromString(Asn1TimeSerializer, json("2026-09-08T05:36:00Z"))
                .instant.toString() shouldBe "2026-09-08T05:36:00Z"
            shouldThrow<SerializationException> {
                Json.decodeFromString(Asn1TimeSerializer, json("9".repeat(1024)))
            }

            (Asn1RealStringSerializer.decodingLimit < DEFAULT_FALLBACK_DECODING_LIMIT) shouldBe true
            shouldThrow<SerializationException> {
                Json.decodeFromString(
                    Asn1RealStringSerializer,
                    json("f".repeat(Asn1RealStringSerializer.decodingLimit) + " * 2^1"),
                )
            }
        }

        "quadratic decimal INTEGER decoding has the tighter limit" {
            (Asn1IntegerDecimalStringSerializer.decodingLimit < Asn1IntegerHexStringSerializer.decodingLimit)
                .shouldBe(true)
            Asn1IntegerHexStringSerializer.decodingLimit shouldBe DEFAULT_FALLBACK_DECODING_LIMIT
        }
    }

    "cheap serializers track the shared default" {
        Asn1IntegerHexStringSerializer.decodingLimit shouldBe BoundedFallbackSerializer.defaultDecodingLimit
        Asn1Utf8StringSerializer.decodingLimit shouldBe BoundedFallbackSerializer.defaultDecodingLimit
        Asn1ElementFallbackBase64Serializer.decodingLimit shouldBe BoundedFallbackSerializer.defaultDecodingLimit
    }

    "bounded serializer does not mutate its singleton" {
        shouldThrow<SerializationException> {
            Json.decodeFromString(ObjectIdentifierStringSerializer.bounded(4), json("1.2.840.113549"))
        }
        Json.decodeFromString(ObjectIdentifierStringSerializer, json("1.2.840.113549"))
            .toString() shouldBe "1.2.840.113549"
    }

}
