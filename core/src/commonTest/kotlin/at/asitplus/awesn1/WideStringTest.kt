package at.asitplus.awesn1

import at.asitplus.awesn1.encoding.decodeToBmpString
import at.asitplus.awesn1.encoding.decodeToUniversalString
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

val WideStringTest by matrixSuite {
    "BMPString uses UCS-2BE and rejects invalid content" {
        Asn1String.BMP("A").encodeToTlv().derEncoded.toHexString() shouldBe "1e020041"
        Asn1String.BMP("Müller").value shouldBe "Müller"
        shouldThrow<Asn1Exception> { Asn1Primitive(Asn1Element.Tag.STRING_BMP, byteArrayOf(0)).decodeToBmpString() }
        shouldThrow<Asn1Exception> { Asn1Primitive(Asn1Element.Tag.STRING_BMP, byteArrayOf(0xd8.toByte(), 0)).decodeToBmpString() }
        shouldThrow<Asn1Exception> { Asn1String.BMP("\uD83D\uDE00") }
    }

    "UniversalString uses UCS-4BE and rejects invalid content" {
        Asn1String.Universal("A").encodeToTlv().derEncoded.toHexString() shouldBe "1c0400000041"
        val smile = Asn1String.Universal("\uD83D\uDE00")
        smile.encodeToTlv().derEncoded.toHexString() shouldBe "1c040001f600"
        smile.value shouldBe "\uD83D\uDE00"
        shouldThrow<Asn1Exception> { Asn1Primitive(Asn1Element.Tag.STRING_UNIVERSAL, byteArrayOf(0)).decodeToUniversalString() }
        shouldThrow<Asn1Exception> { Asn1Primitive(Asn1Element.Tag.STRING_UNIVERSAL, byteArrayOf(0, 0x11, 0, 0)).decodeToUniversalString() }
        shouldThrow<Asn1Exception> { Asn1Primitive(Asn1Element.Tag.STRING_UNIVERSAL, byteArrayOf(0, 0, 0xd8.toByte(), 0)).decodeToUniversalString() }
        shouldThrow<Asn1Exception> { Asn1String.Universal("\uD800") }
    }
}
