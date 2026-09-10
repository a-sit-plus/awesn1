// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json

private inline fun shouldFailSerialization(block: () -> Unit) {
    shouldThrow<SerializationException>(block)
}

val FallbackExceptionContract by matrixSuite {
    "malformed OIDs fail as SerializationException" {
        for (value in listOf("1.2." + "9".repeat(200), "1.2.x", "1", "", "5.1.2")) {
            shouldFailSerialization { Json.decodeFromString(ObjectIdentifier.serializer(), "\"$value\"") }
        }
    }

    "malformed base64 elements fail as SerializationException" {
        for (value in listOf("MoA=", "MBU=", "CYEB", "@@not-base64@@")) {
            shouldFailSerialization {
                Json.decodeFromString(Asn1ElementFallbackBase64Serializer, "\"$value\"")
            }
        }
    }

    "malformed bit strings fail as SerializationException" {
        for (value in listOf("6:IA==", "1", "99999999999999:AAAA", "1:!!!", "8:AAAA")) {
            shouldFailSerialization { Json.decodeFromString(Asn1BitString.serializer(), "\"$value\"") }
        }
        Json.decodeFromString(Asn1BitString.serializer(), "\"0:AAAA\"").bitCarryingBytes.size shouldBe 3
    }

    "malformed decimal INTEGERs fail as SerializationException" {
        for (value in listOf("12x34", "")) {
            shouldFailSerialization {
                Json.decodeFromString(Asn1IntegerDecimalStringSerializer, "\"$value\"")
            }
        }
    }

    "malformed timestamps fail as SerializationException" {
        for (value in listOf("not-a-time", "2020-13-99T99:99:99Z")) {
            shouldFailSerialization { Json.decodeFromString(Asn1Time.Companion, "\"$value\"") }
        }
    }

    "accepted decimal INTEGERs can be encoded again" {
        val atLimit = Asn1Integer.fromUnsignedByteArray(
            ByteArray(Asn1IntegerDecimalStringSerializer.encodingLimit).also { it[0] = 1 }
        )
        val json = Json.encodeToString(Asn1IntegerDecimalStringSerializer, atLimit)
        Json.encodeToString(
            Asn1IntegerDecimalStringSerializer,
            Json.decodeFromString(Asn1IntegerDecimalStringSerializer, json),
        ) shouldBe json
    }
}
