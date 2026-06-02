package at.asitplus.awesn1.at.asitplus.awesn1.hardening

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.encoding.decodeFromDer
import at.asitplus.awesn1.parseFromDerHexString
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

private data class OidVector(
    val name: String,
    val tlvHex: String,
    val expectedOid: String? = null,
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
        ) - { (hex, string) ->
            "case" {
            val parsed = ObjectIdentifier.decodeFromDer(hex)
            parsed.toString() shouldBe string
            ObjectIdentifier(string) shouldBe parsed
            ObjectIdentifier(string).toString() shouldBe string
            }
        }
    }

    "accepts minimally encoded OID arcs" - {
        data(
            "vector",
            listOf(
                OidVector("single-byte-tail-arc", "06 02 2B 18", "1.3.24"),
                OidVector("minimal-two-byte-tail-arc-128", "06 03 2B 81 00", "1.3.128"),
                OidVector("minimal-two-byte-tail-arc-311", "06 03 2B 82 37", "1.3.311"),
                OidVector("minimal-three-byte-tail-arc-16384", "06 04 2B 81 80 00", "1.3.16384"),
            ),
            nameFn = { _, it -> it.name },
        ) - { (_, tlvHex, expectedOid) ->
            "case" {
            ObjectIdentifier.decodeFromTlv(Asn1Element.parseFromDerHexString(tlvHex).asPrimitive())
                .toString() shouldBe expectedOid
            }
        }
    }

    "rejects non-minimal base128 OID arcs" - {
        data(
            "vector",
            listOf(
                OidVector("leading-zero-before-single-byte-value", "06 03 2B 80 18"),
                OidVector("leading-zero-before-zero", "06 03 2B 80 00"),
                OidVector("leading-zero-before-two-byte-value", "06 04 2B 80 81 00"),
                OidVector("two-leading-zero-groups", "06 04 2B 80 80 18"),
            ),
            nameFn = { _, it -> it.name },
        ) - { (_, tlvHex) ->
            "case" {
            shouldThrow<Asn1Exception> {
                ObjectIdentifier.decodeFromTlv(Asn1Element.parseFromDerHexString(tlvHex).asPrimitive())
            }.message shouldBe "OID node is not minimally encoded"
            }
        }
    }

    "rejects unterminated OID arcs" - {
        data(
            "vector",
            listOf(
                OidVector("tail-arc-only-continuation-byte", "06 02 2B 81"),
                OidVector("tail-arc-only-continuation-bytes", "06 03 2B 81 80"),
            ),
            nameFn = { _, it -> it.name },
        ) - { (_, tlvHex) ->
            "case" {
            shouldThrow<Asn1Exception> {
                ObjectIdentifier.decodeFromTlv(Asn1Element.parseFromDerHexString(tlvHex).asPrimitive())
            }.message shouldBe "Encoded OID does not end with a valid ASN.1 varint"
            }
        }
    }
}
