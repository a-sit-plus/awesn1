package at.asitplus.awesn1.hardening

import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1IntegerDecimalStringSerializer
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.ObjectIdentifierStringSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json

/**
 * The String-based (non-DER) serializers for INTEGER and OBJECT IDENTIFIER must emit the exact value or fail
 * loudly: they **throw** over the conversion cap rather than truncating or emitting a placeholder, so a JSON (or
 * other string-format) round-trip is always lossless or a hard error — never silent corruption.
 */
val SerializerCapTest by matrixSuite {

    "Asn1IntegerDecimalStringSerializer throws for an over-cap magnitude (never truncates)" {
        val overCap = Asn1Integer.fromUnsignedByteArray(
            ByteArray(Asn1IntegerDecimalStringSerializer.encodingLimit + 1).also { it[0] = 0x01 }
        )
        shouldThrow<Asn1Exception> { Json.encodeToString(Asn1IntegerDecimalStringSerializer, overCap) }
    }

    check(Asn1IntegerDecimalStringSerializer.decodingLimit >= 500)
    "Asn1IntegerDecimalStringSerializer round-trips an in-cap value" {
        val v = Asn1Integer.fromDecimalString("1234567890".repeat(50)) // 500 digits, well within cap
        val json = Json.encodeToString(Asn1IntegerDecimalStringSerializer, v)
        Json.decodeFromString(Asn1IntegerDecimalStringSerializer, json) shouldBe v
    }

    "ObjectIdentifier construction rejects an excessive sub-identifier" {
        shouldThrow<Asn1Exception> { ObjectIdentifier("2.25." + "9".repeat(ObjectIdentifier.MAX_SUBIDENTIFIER_CHARS+1)) }
    }

    "over-cap OIDs cannot be constructed, so string (de)serialization stays bounded by construction" {
        // The serializer itself needs no cap check; deserializing an over-cap arc throws at construction.
        shouldThrow<Asn1Exception> {
            Json.decodeFromString(ObjectIdentifierStringSerializer, "\"2.25.${"9".repeat(200)}\"")
        }
    }

    "ObjectIdentifierStringSerializer round-trips a normal OID (incl. a UUID-scale 2.25 arc)" {
        for (oid in listOf(ObjectIdentifier("1.2.840.113549.1.1.11"), ObjectIdentifier("2.25." + "9".repeat(39)))) {
            val json = Json.encodeToString(ObjectIdentifierStringSerializer, oid)
            Json.decodeFromString(ObjectIdentifierStringSerializer, json) shouldBe oid
        }
    }
}
