// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(ExperimentalStdlibApi::class)

package at.asitplus.awesn1.hardening

import at.asitplus.awesn1.Asn1CustomStructureFallbackBase64Serializer
import at.asitplus.awesn1.Asn1IntegerHexStringSerializer
import at.asitplus.awesn1.Asn1OctetStringFallbackBase64Serializer
import at.asitplus.awesn1.Asn1RealStringSerializer
import at.asitplus.awesn1.Asn1PrintableStringSerializer
import at.asitplus.awesn1.Asn1VisibleStringSerializer
import at.asitplus.awesn1.Asn1Ia5StringSerializer
import at.asitplus.awesn1.Asn1NumericStringSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json

val fallback_b64_serializer_leaks_raw_asn1exception by matrixSuite {
    for (payload in listOf("hQQCAQD/", "hQICAQ==")) {
        "Malformed deferred child content $payload fails as SerializationException" {
            shouldThrow<SerializationException> {
                Json.decodeFromString(Asn1CustomStructureFallbackBase64Serializer, "\"$payload\"")
            }
        }
    }
}

val kxs_octetstring_fallback_unchecked_cast_cce by matrixSuite {
    "A base64 OCTET STRING decodes successfully" {
        Json.decodeFromString(Asn1OctetStringFallbackBase64Serializer, "\"BAMBAgM=\"")
            .content.toHexString() shouldBe "010203"
    }

    "A base64 SEQUENCE in an OCTET STRING slot fails as SerializationException" {
        shouldThrow<SerializationException> {
            Json.decodeFromString(Asn1OctetStringFallbackBase64Serializer, "\"MAMCAQE=\"")
        }
    }
}

val kxs_hex_int_zerodigit_oob_asn1exception_leak_v2 by matrixSuite {
    for (value in listOf(":", "0x:", "+:")) {
        "A zero-digit hex INTEGER $value fails as SerializationException" {
            shouldThrow<SerializationException> {
                Json.decodeFromString(Asn1IntegerHexStringSerializer, "\"$value\"")
            }
        }
    }
}

val real_string_serializer_exception_leak by matrixSuite {
    for (value in listOf(":*2^0", "0xzz*2^0", "not-a-real", "*2^0", "0x1*2^zz")) {
        "Malformed REAL text $value fails as SerializationException" {
            shouldThrow<SerializationException> {
                Json.decodeFromString(Asn1RealStringSerializer, "\"$value\"")
            }
        }
    }
}

val string_serializers_json_leak_raw_asn1exception by matrixSuite {
    "Invalid PrintableString content fails as SerializationException" {
        shouldThrow<SerializationException> { Json.decodeFromString(Asn1PrintableStringSerializer, "\"café\"") }
    }

    "Invalid VisibleString content fails as SerializationException" {
        shouldThrow<SerializationException> { Json.decodeFromString(Asn1VisibleStringSerializer, "\"\\u0001x\"") }
    }

    "Invalid IA5String content fails as SerializationException" {
        shouldThrow<SerializationException> { Json.decodeFromString(Asn1Ia5StringSerializer, "\"é\"") }
    }

    "Invalid NumericString content fails as SerializationException" {
        shouldThrow<SerializationException> { Json.decodeFromString(Asn1NumericStringSerializer, "\"a1\"") }
    }
}
