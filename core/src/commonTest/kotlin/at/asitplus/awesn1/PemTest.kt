package at.asitplus.awesn1

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

val PemTest by testSuite {

    "round trip pem block with headers" {
        val block = PemBlock(
            label = "RSA PRIVATE KEY",
            headers = listOf(
                PemHeader("Proc-Type", "4,ENCRYPTED"),
                PemHeader("DEK-Info", "AES-256-CBC,00112233445566778899AABBCCDDEEFF")
            ),
            payload = byteArrayOf(1, 2, 3, 4, 5)
        )

        val encoded = block.encodeToPem()
        val decoded = decodeFromPem(encoded)

        decoded.label shouldBe block.label
        decoded.headers shouldBe block.headers
        (decoded.payload contentEquals block.payload) shouldBe true
    }

    "decode all supports mixed labels" {
        val cert = PemBlock("CERTIFICATE", payload = byteArrayOf(1, 2, 3))
        val key = PemBlock("PRIVATE KEY", payload = byteArrayOf(4, 5, 6))

        val src = listOf(cert, key).encodeAllToPem()
        val decoded = decodeAllFromPem(src)

        decoded.size shouldBe 2
        decoded[0].label shouldBe "CERTIFICATE"
        decoded[1].label shouldBe "PRIVATE KEY"
        (decoded[0].payload contentEquals byteArrayOf(1, 2, 3)) shouldBe true
        (decoded[1].payload contentEquals byteArrayOf(4, 5, 6)) shouldBe true
    }

    "boundary mismatch fails" {
        val src = """
            -----BEGIN CERTIFICATE-----
            AQID
            -----END PRIVATE KEY-----
        """.trimIndent()

        shouldThrow<IllegalArgumentException> {
            decodeFromPem(src)
        }
    }

    "asn1 bridge works with opaque pem parser" {
        val source = object : Asn1PemEncodable<Asn1Primitive> {
            override val pemLabel: String = "ASN1 INTEGER"
            override fun encodeToTlv(): Asn1Primitive = Asn1Integer(7).encodeToTlv()
        }

        val decoder = object : Asn1PemDecodable<Asn1Primitive, Asn1Integer>,
            Asn1Decodable<Asn1Primitive, Asn1Integer> by Asn1Integer.Companion {}

        decoder.decodeFromPem(source.encodeToPem()) shouldBe Asn1Integer(7)
    }

    "pem header uses value equality" {
        PemHeader("Proc-Type", "4,ENCRYPTED") shouldBe PemHeader("Proc-Type", "4,ENCRYPTED")
        PemHeader("Proc-Type", "4,ENCRYPTED") shouldNotBe PemHeader("DEK-Info", "AES-256-CBC,AA")
    }

    "pem block uses payload content equality" {
        val a = PemBlock(
            label = "CERTIFICATE",
            headers = listOf(PemHeader("X-Test", "1")),
            payload = byteArrayOf(1, 2, 3)
        )
        val b = PemBlock(
            label = "CERTIFICATE",
            headers = listOf(PemHeader("X-Test", "1")),
            payload = byteArrayOf(1, 2, 3)
        )
        val c = PemBlock(
            label = "CERTIFICATE",
            headers = listOf(PemHeader("X-Test", "1")),
            payload = byteArrayOf(1, 2, 4)
        )

        a shouldBe b
        a.hashCode() shouldBe b.hashCode()
        a shouldNotBe c
    }
}
