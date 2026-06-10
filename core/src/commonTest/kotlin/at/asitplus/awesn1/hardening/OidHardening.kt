package at.asitplus.awesn1.hardening

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.encoding.decodeFromDer
import at.asitplus.awesn1.encoding.encodeToDer
import at.asitplus.awesn1.toDerHexString
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

private data class OidVector(
    val name: String,
    val tlvHex: String,
    val expectedOid: String? = null,
)

private data class OidStringVector(
    val oid: String,
    val normalizedOid: String,
    val tlvHex: String,
)

private data class InvalidOidStringVector(
    val name: String,
    val oid: String,
)

val OidHardening by matrixSuite {

    "manual arc 2" - {
        data(
            "oid",
            listOf(
                "0630848080808080808080808080808080808080309b9b9bf9b9ff30b9303030302b8104001f303030303030303030060100".hexToByteArray() to "2.340282366920938463463374607431768211424.119682471198640.7344.48.48.48.43.132.0.31.48.48.48.48.48.48.48.48.48.6.1.0",
                "0607ffff3032301006".hexToByteArray() to "2.2096992.50.48.16.6",
                "060485393232".hexToByteArray() to "2.617.50.50",
            ),
            nameFn = { _, (_, string) -> string },
        ) test { (hex, string) ->
            val parsed = ObjectIdentifier.decodeFromDer(hex)
            parsed.toString() shouldBe string
            ObjectIdentifier(string) shouldBe parsed
            ObjectIdentifier(string).toString() shouldBe string
        }
    }

    compact("accepts minimally encoded OID arcs" )- {
        data(
            listOf(
                OidVector("single-byte-tail-arc", "06 02 2B 18", "1.3.24"),
                OidVector("minimal-two-byte-tail-arc-128", "06 03 2B 81 00", "1.3.128"),
                OidVector("minimal-two-byte-tail-arc-311", "06 03 2B 82 37", "1.3.311"),
                OidVector("minimal-three-byte-tail-arc-16384", "06 04 2B 81 80 00", "1.3.16384"),

                // First subidentifier boundaries / arc 2 mapping.
                OidVector("root-0-second-0", "06 01 00", "0.0"),
                OidVector("root-0-second-39", "06 01 27", "0.39"),
                OidVector("root-1-second-0", "06 01 28", "1.0"),
                OidVector("root-1-second-39", "06 01 4F", "1.39"),
                OidVector("root-1-second-2", "06 01 2A", "1.2"),
                OidVector("root-2-second-0", "06 01 50", "2.0"),
                OidVector("root-2-second-39", "06 01 77", "2.39"),
                OidVector("root-2-second-40", "06 01 78", "2.40"),
                OidVector("root-2-second-47", "06 01 7F", "2.47"),
                OidVector("root-2-second-48", "06 02 81 00", "2.48"),
                OidVector("root-2-second-999", "06 02 88 37", "2.999"),

                // Common-ish OIDs.
                OidVector("rsa-encryption-prefix", "06 06 2A 86 48 86 F7 0D", "1.2.840.113549"),
                OidVector("common-name", "06 03 55 04 03", "2.5.4.3"),
                OidVector("sha256", "06 09 60 86 48 01 65 03 04 02 01", "2.16.840.1.101.3.4.2.1"),
            ),
            nameFn = { _, it -> it.name },
        ) test { (_, tlvHex, expectedOid) ->
            ObjectIdentifier.decodeFromTlv(Asn1Element.parseFromDerHexString(tlvHex).asPrimitive())
                .toString() shouldBe expectedOid
        }
    }

    compact("string constructor encodes valid OIDs canonically") - {
        data(
            listOf(
                OidStringVector("0.0", "0.0", "060100"),
                OidStringVector("0.39", "0.39", "060127"),
                OidStringVector("1.0", "1.0", "060128"),
                OidStringVector("1.39", "1.39", "06014f"),
                OidStringVector("1.2", "1.2", "06012a"),

                // Arc 2: second arc is not restricted to 0..39.
                OidStringVector("2.0", "2.0", "060150"),
                OidStringVector("2.39", "2.39", "060177"),
                OidStringVector("2.40", "2.40", "060178"),
                OidStringVector("2.47", "2.47", "06017f"),
                OidStringVector("2.48", "2.48", "06028100"),
                OidStringVector("2.999", "2.999", "06028837"),

                // Common-ish OIDs.
                OidStringVector("1.2.840.113549", "1.2.840.113549", "06062a864886f70d"),
                OidStringVector("2.5.4.3", "2.5.4.3", "0603550403"),
                OidStringVector("2.16.840.1.101.3.4.2.1", "2.16.840.1.101.3.4.2.1", "0609608648016503040201"),

                // Decimal arc normalization from textual input.
                OidStringVector("01.02.000840", "1.2.840", "06032a8648"),
                OidStringVector("2.000048", "2.48", "06028100"),
            ),
            nameFn = { _, it -> it.oid },
        ) test { vector ->
            val oid = ObjectIdentifier(vector.oid)

            oid.toString() shouldBe vector.normalizedOid
            oid.toDerHexString().lowercase() shouldBe vector.tlvHex
        }
    }

    compact("space separated OID strings are accepted") - {
        data(
            listOf(
                OidStringVector("0 0", "0.0", "060100"),
                OidStringVector("1 2 840 113549", "1.2.840.113549", "06062a864886f70d"),
                OidStringVector("2 48", "2.48", "06028100"),
                OidStringVector("2 999", "2.999", "06028837"),
            ),
            nameFn = { _, it -> it.oid },
        ) test { vector ->
            val oid = ObjectIdentifier(vector.oid)

            oid.toString() shouldBe vector.normalizedOid
            oid.toDerHexString().lowercase() shouldBe vector.tlvHex
        }
    }

    compact("string constructor rejects invalid OIDs") - {
        data(
            listOf(
                InvalidOidStringVector("empty string", ""),
                InvalidOidStringVector("only one arc 0", "0"),
                InvalidOidStringVector("only one arc 1", "1"),
                InvalidOidStringVector("only one arc 2", "2"),

                InvalidOidStringVector("first arc 3", "3.0"),
                InvalidOidStringVector("first arc 4", "4.1"),

                InvalidOidStringVector("arc 0 second 40", "0.40"),
                InvalidOidStringVector("arc 1 second 40", "1.40"),
                InvalidOidStringVector("arc 0 second huge", "0.999"),
                InvalidOidStringVector("arc 1 second huge", "1.999"),

                InvalidOidStringVector("negative first arc", "-1.2"),
                InvalidOidStringVector("negative second arc", "1.-2"),
                InvalidOidStringVector("negative tail arc", "1.2.-3"),

                InvalidOidStringVector("non-numeric arc", "1.two.3"),
                InvalidOidStringVector("empty middle arc", "1..2"),
                InvalidOidStringVector("leading dot", ".1.2"),
                InvalidOidStringVector("trailing dot", "1.2."),

                // Current constructor chooses separator by contains('.'), so mixed separators should fail.
                InvalidOidStringVector("mixed dot-space", "1.2 840"),
                InvalidOidStringVector("mixed space-dot", "1 2.840"),
            ),
            nameFn = { _, it -> it.name },
        ) test { vector ->
            shouldThrow<Throwable> {
                ObjectIdentifier(vector.oid)
            }
        }
    }

    compact("OID string and raw DER roundtrip") - {
        data(
            listOf(
                OidStringVector("0.0", "0.0", "060100"),
                OidStringVector("1.2", "1.2", "06012a"),
                OidStringVector("2.48", "2.48", "06028100"),
                OidStringVector("1.2.840.113549", "1.2.840.113549", "06062a864886f70d"),
                OidStringVector("2.999", "2.999", "06028837"),
            ),
            nameFn = { _, it -> it.oid },
        ) test { vector ->
            val fromString = ObjectIdentifier(vector.oid)
            val fromDer = ObjectIdentifier.decodeFromTlv(
                Asn1Element.parseFromDerHexString(vector.tlvHex).asPrimitive()
            )

            fromDer.toString() shouldBe vector.normalizedOid
            fromDer shouldBe fromString
            fromDer.toDerHexString().lowercase() shouldBe vector.tlvHex
        }
    }

    compact("rejects non-minimal base128 OID arcs") - {
        data(
            listOf(
                OidVector("leading-zero-before-single-byte-value", "06 03 2B 80 18"),
                OidVector("leading-zero-before-zero", "06 03 2B 80 00"),
                OidVector("leading-zero-before-two-byte-value", "06 04 2B 80 81 00"),
                OidVector("two-leading-zero-groups", "06 04 2B 80 80 18"),

                // Non-minimal first subidentifier cases.
                OidVector("non-minimal-first-subidentifier-42", "06 02 80 2A"),
                OidVector("first-subidentifier-leading-zero-only", "06 01 80"),
            ),
            nameFn = { _, it -> it.name },
        ) test { (_, tlvHex) ->
            shouldThrow<Asn1Exception> {
                ObjectIdentifier.decodeFromTlv(Asn1Element.parseFromDerHexString(tlvHex).asPrimitive())
            }.message shouldBe "OID node is not minimally encoded"
        }
    }

   compact( "rejects unterminated OID arcs") - {
        data(
            listOf(
                OidVector("tail-arc-only-continuation-byte", "06 02 2B 81"),
                OidVector("tail-arc-only-continuation-bytes", "06 03 2B 81 80"),

                // Unterminated first subidentifier, but not a leading-zero group.
                OidVector("first-subidentifier-only-continuation-byte", "06 01 81"),
                OidVector("first-subidentifier-only-continuation-bytes", "06 02 81 80"),
            ),
            nameFn = { _, it -> it.name },
        ) test { (_, tlvHex) ->
            shouldThrow<Asn1Exception> {
                ObjectIdentifier.decodeFromTlv(Asn1Element.parseFromDerHexString(tlvHex).asPrimitive())
            }.message shouldBe "Encoded OID does not end with a valid ASN.1 varint"
        }
    }

    "rejects empty OID content" - {
        data(
            listOf(
                OidVector("empty-oid-content", "06 00"),
            ),
            nameFn = { _, it -> it.name },
        ) test { (_, tlvHex) ->
            shouldThrow<Asn1Exception> {
                ObjectIdentifier.decodeFromTlv(Asn1Element.parseFromDerHexString(tlvHex).asPrimitive())
            }
        }
    }
}