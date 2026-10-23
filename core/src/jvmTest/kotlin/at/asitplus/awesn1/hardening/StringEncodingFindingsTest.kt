// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(ExperimentalStdlibApi::class)

package at.asitplus.awesn1

import at.asitplus.awesn1.encoding.decodeToBmpString
import at.asitplus.awesn1.encoding.parse
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json

// Suite names preserve the original finding identifiers.
val bmp_universal_string_utf8_content by matrixSuite {
    "BMPString encoding uses UCS-2BE" {
        Asn1String.BMP("A").encodeToTlv().derEncoded.toHexString() shouldBe "1e020041"
    }

    "Conformant UCS-2BE content decodes without mojibake" {
        val conformant = "1e0c004d00fc006c006c00650072".hexToByteArray()
        (Asn1Element.parse(conformant) as Asn1Primitive).decodeToBmpString().value shouldBe "Müller"
    }
}

val string_decode_value_utf8_misdecode by matrixSuite {
    val a = Asn1Primitive(Asn1Element.Tag.STRING_BMP, "00c4".hexToByteArray())
    val b = Asn1Primitive(Asn1Element.Tag.STRING_BMP, "00c5".hexToByteArray())

    "A UCS-2BE code unit decodes to its character" {
        Asn1Primitive(Asn1Element.Tag.STRING_BMP, "0041".hexToByteArray())
            .decodeToBmpString().value shouldBe "A"
    }

    "Distinct BMPString content remains unequal" {
        a.decodeToBmpString() shouldNotBe b.decodeToBmpString()
    }
}

val implicit_utf8_decode_silently_rewrites_bytes by matrixSuite {
    val tag = Asn1Element.Tag(0uL, constructed = false, tagClass = TagClass.CONTEXT_SPECIFIC)
    val malformed = byteArrayOf(0x41, 0xC0.toByte(), 0x80.toByte(), 0x42)

    "Implicit UTF8String content rejects an overlong encoding" {
        shouldThrow<Asn1Exception> {
            Asn1Utf8StringSerializer.decodeFromTlv(Asn1Primitive(tag, malformed), null)
        }
    }

    "Implicit UTF8String content rejects a stray continuation byte" {
        shouldThrow<Asn1Exception> {
            Asn1Utf8StringSerializer.decodeFromTlv(Asn1Primitive(tag, byteArrayOf(0x80.toByte())), null)
        }
    }
}

val utf8_serializer_lone_surrogate_silent_mutation by matrixSuite {
    "Valid UTF8String text round-trips through JSON" {
        Json.encodeToString(
            Asn1Utf8StringSerializer,
            Json.decodeFromString(Asn1Utf8StringSerializer, "\"héllo\""),
        ) shouldBe "\"héllo\""
    }

    "A lone surrogate produces SerializationException with an Asn1Exception cause" {
        val thrown = shouldThrow<SerializationException> {
            Json.decodeFromString(Asn1Utf8StringSerializer, "\"a\\ud800b\"")
        }
        thrown.cause.shouldBeInstanceOf<Asn1Exception>()
    }
}

val string_implicit_tag_gate_fails_open by matrixSuite {
    val octetString = Asn1Primitive(Asn1Element.Tag.OCTET_STRING, "admin".encodeToByteArray())

    "A mismatched foreign string tag is rejected" {
        shouldThrow<Asn1Exception> {
            Asn1Utf8StringSerializer.decodeFromTlv(octetString, Asn1Element.Tag.STRING_PRINTABLE)
        }
    }

    "An asserted UTF8String tag rejects OCTET STRING input" {
        shouldThrow<Asn1Exception> {
            Asn1Utf8StringSerializer.decodeFromTlv(octetString, Asn1Element.Tag.STRING_UTF8)
        }
    }
}
