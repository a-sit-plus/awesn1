package at.asitplus.awesn1.at.asitplus.awesn1.hardening

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.encoding.decodeFromDer
import at.asitplus.awesn1.parseFromDerHexString
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

private data class OidVector(
    val name: String,
    val tlvHex: String,
    val expectedOid: String? = null,
)

val OidHardening by testSuite {

    "manual arc 2" - {
        withData(nameFn = {(_,str)->str},"0630848080808080808080808080808080808080309b9b9bf9b9ff30b9303030302b8104001f303030303030303030060100".hexToByteArray() to "2.340282366920938463463374607431768211424.119682471198640.7344.48.48.48.43.132.0.31.48.48.48.48.48.48.48.48.48.6.1.0",
            "0607ffff3032301006".hexToByteArray() to "2.2096992.50.48.16.6",
            "060485393232".hexToByteArray() to "2.617.50.50", compact = false) {(hex, string) ->
            val parsed = ObjectIdentifier.decodeFromDer(hex)
            parsed.toString() shouldBe string
            ObjectIdentifier(string) shouldBe parsed
            ObjectIdentifier(string).toString() shouldBe string
        }
    }

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
