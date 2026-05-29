package at.asitplus.awesn1.at.asitplus.awesn1.hardening

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

private data class OidVector(
    val name: String,
    val tlvHex: String,
    val expectedOid: String? = null,
)

val OidHardening by testSuite {
    "accepts minimally encoded OID arcs" - {
        withData(
            OidVector("single-byte-tail-arc", "06 02 2B 18", "1.3.24"),
            OidVector("minimal-two-byte-tail-arc-128", "06 03 2B 81 00", "1.3.128"),
            OidVector("minimal-two-byte-tail-arc-311", "06 03 2B 82 37", "1.3.311"),
            OidVector("minimal-three-byte-tail-arc-16384", "06 04 2B 81 80 00", "1.3.16384"),
            compact = false
        ) { (_, tlvHex, expectedOid) ->
            ObjectIdentifier.decodeFromTlv(Asn1Element.parseFromDerHexString(tlvHex).asPrimitive())
                .toString() shouldBe expectedOid
        }
    }

    "rejects non-minimal base128 OID arcs" - {
        withData(
            OidVector("leading-zero-before-single-byte-value", "06 03 2B 80 18"),
            OidVector("leading-zero-before-zero", "06 03 2B 80 00"),
            OidVector("leading-zero-before-two-byte-value", "06 04 2B 80 81 00"),
            OidVector("two-leading-zero-groups", "06 04 2B 80 80 18"),
            compact = false
        ) { (_, tlvHex) ->
            shouldThrow<Asn1Exception> {
                ObjectIdentifier.decodeFromTlv(Asn1Element.parseFromDerHexString(tlvHex).asPrimitive())
            }.message shouldBe "OID node is not minimally encoded"
        }
    }

    "rejects unterminated OID arcs" - {
        withData(
            OidVector("tail-arc-only-continuation-byte", "06 02 2B 81"),
            OidVector("tail-arc-only-continuation-bytes", "06 03 2B 81 80"),
            compact = false
        ) { (_, tlvHex) ->
            shouldThrow<Asn1Exception> {
                ObjectIdentifier.decodeFromTlv(Asn1Element.parseFromDerHexString(tlvHex).asPrimitive())
            }.message shouldBe "Encoded OID does not end with a valid ASN.1 varint"
        }
    }
}
