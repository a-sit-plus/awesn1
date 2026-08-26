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
        elementPaths(decoded.element) shouldBe listOf("0", "0.0")

        val encapsulated = decodeInput("04 03 02 01 01", InputFormat.HEX).element
        elementPaths(encapsulated) shouldBe listOf("0")
        coloredHex(encapsulated).first.map { it.path } shouldBe listOf("0", "0", "0.0", "0.0", "0.0")
    }
}
