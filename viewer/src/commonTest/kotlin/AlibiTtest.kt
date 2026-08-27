package at.asitplus.awesn1.viewer

import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.describeAll
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.assertions.throwables.shouldThrow

val alibi by matrixSuite {
    "decodes hex, base64, PEM, and auto formats" {
        val der = byteArrayOf(0x30, 0x03, 0x02, 0x01, 0x01)
        decodeInput("30 03:02 01 01", InputFormat.HEX).bytes.toList() shouldBe der.toList()
        decodeInput("MAMCAQE=", InputFormat.BASE64).bytes.toList() shouldBe der.toList()
        val pem = decodeInput("-----BEGIN TEST-----\n\nMAMCAQE=\n-----END TEST-----", InputFormat.PEM)
        pem.bytes.toList() shouldBe der.toList()
        pem.pemLabel shouldBe "TEST"
        pem.element.prettyPrint().contains("Sequence") shouldBe true
        decodeInput("MAMCAQE=", InputFormat.AUTO).bytes.toList() shouldBe der.toList()
    }

    "rejects malformed input" {
        shouldThrow<IllegalArgumentException> { decodeInput("abc", InputFormat.HEX) }
        shouldThrow<IllegalArgumentException> { decodeInput("-----BEGIN A-----\nMAMCAQE=\n-----END B-----", InputFormat.PEM) }
    }

    "loads OID descriptions and colors exact DER bytes" {
        KnownOIDs.describeAll()
        KnownOIDs[ObjectIdentifier("2.5.4.3")]?.isNotBlank() shouldBe true
        val decoded = decodeInput("30 03 02 01 01", InputFormat.HEX)
        coloredHex(decoded.element).first.map { it.value }.toByteArray().toList() shouldBe decoded.bytes.toList()
        coloredHex(decoded.element).first.map { it.path } shouldBe listOf("0", "0", "0.0", "0.0", "0.0")
        genericAsn1Lines(decoded.element).mapNotNull { it.path } shouldBe listOf("0", "0.0")

        val encapsulated = decodeInput("04 03 02 01 01", InputFormat.HEX).element
        genericAsn1Lines(encapsulated).mapNotNull { it.path } shouldBe listOf("0", "0.0")
        coloredHex(encapsulated).first.map { it.path } shouldBe listOf("0", "0", "0.0", "0.0", "0.0")
    }

    "maps nested CSR elements to their exact DER range" {
        val csr = decodeInput(
            "MIHQMIGDAgEAMA8xDTALBgNVBAMMBHRlc3QwKjAFBgMrZXADIQD7Fua9ZF+wPXVd" +
                    "DCBwQr+Aqny6OFvs25wZ/P4LyVsYmKBBMD8GCSqGSIb3DQEJDjEyMDAwLgYDVR0R" +
                    "BCcwJaAjBgorBgEEAYI3FAIDoBUME2FkZHJlc3NAZG9tYWluLnRlc3QwBQYDK2Vw" +
                    "A0EAUp5FenHF1rZzRGU+7wiF+/D1bfyDRF0dzWz2sl44nltu8iLjHO3aIfOTYWpq" +
                    "ZlaDg1Bq3L7Fcb7If4yZAsE5Cw==",
            InputFormat.BASE64,
        )
        val tagged = genericAsn1Lines(csr.element).single {
            it.text.contains("CONTEXT_SPECIFIC 0") && it.byteLength == 23
        }
        tagged.byteOffset shouldBe 114
        coloredHex(csr.element).first[114].path shouldBe tagged.path
        coloredHex(csr.element).first.slice(114..136).all {
            it.path == tagged.path || it.path.startsWith("${tagged.path}.")
        } shouldBe true
        val names = schemaMemberNames(csr.bytes, csr.element)
        names["0.0"] shouldBe "certificationRequestInfo"
        names["0.0.2"] shouldBe "subjectPKInfo"
        names["0.1"] shouldBe "signatureAlgorithm"
        names["0.2"] shouldBe "signature"
        genericAsn1Lines(csr.element, names).single { it.path == "0.0.2" }.memberName shouldBe "subjectPKInfo"
    }

    "names every supported crypto structure" {
        mapOf(
            "30 06 02 01 03 02 01 03" to "RSAPublicKey",
            "30 06 02 01 01 04 01 01" to "ECPrivateKey",
            "30 1B 02 01 00 02 01 01 02 01 01 02 01 01 02 01 01 02 01 01 02 01 01 02 01 01 02 01 01" to "RSAPrivateKey",
            "30 0C 30 05 06 03 2B 65 70 03 03 00 01 02" to "SubjectPublicKeyInfo",
            "30 0A 30 05 06 03 2B 65 70 04 01 00" to "EncryptedPrivateKeyInfo",
            "30 0E 02 01 00 30 05 06 03 2B 65 70 04 02 04 00" to "PrivateKeyInfo",
        ).forEach { (hex, rootName) ->
            val decoded = decodeInput(hex, InputFormat.HEX)
            schemaMemberNames(decoded.bytes, decoded.element)["0"] shouldBe rootName
        }
    }
}
