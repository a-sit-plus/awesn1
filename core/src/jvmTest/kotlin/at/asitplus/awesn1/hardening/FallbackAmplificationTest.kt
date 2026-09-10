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
    "OBJECT IDENTIFIER still caps individual nodes as part of value validation" {
        shouldThrow<SerializationException> {
            Json.decodeFromString(
                ObjectIdentifierStringSerializer,
                json("1.2." + "9".repeat(ObjectIdentifier.MAX_SUBIDENTIFIER_CHARS + 1)),
            )
        }
    }

    "fallback serializers validate values without imposing an input budget" {
        Json.decodeFromString(Asn1TimeSerializer, json("2026-09-08T05:36:00Z"))
            .instant.toString() shouldBe "2026-09-08T05:36:00Z"
        shouldThrow<SerializationException> {
            Json.decodeFromString(Asn1RealStringSerializer, json("not a REAL"))
        }
    }

    "quadratic decimal INTEGER decoding retains its conversion limit" {
        (Asn1IntegerDecimalStringSerializer.decodingLimit > 0) shouldBe true
    }
}
