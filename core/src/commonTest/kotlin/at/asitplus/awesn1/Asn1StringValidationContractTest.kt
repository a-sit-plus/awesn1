package at.asitplus.awesn1

import at.asitplus.awesn1.encoding.decodeToBmpString
import at.asitplus.awesn1.encoding.decodeToIa5String
import at.asitplus.awesn1.encoding.decodeToTeletextString
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

val Asn1StringValidationContractTest by matrixSuite {
    "generic decoding preserves known-invalid content" {
        val primitive = Asn1Primitive(Asn1Element.Tag.STRING_BMP, byteArrayOf(0))
        val decoded = Asn1String.decodeFromTlv(primitive)

        decoded.shouldBeInstanceOf<Asn1String.BMP>()
        decoded.isValid shouldBe false
        decoded.rawValue.contentEquals(primitive.content) shouldBe true
        decoded.encodeToTlv().derEncoded.contentEquals(primitive.derEncoded) shouldBe true
        shouldThrow<Asn1Exception> { decoded.value }
        shouldThrow<Asn1Exception> { primitive.decodeToBmpString() }
    }

    "specific decoding rejects known-invalid repertoire content" {
        val primitive = Asn1Primitive(Asn1Element.Tag.STRING_IA5, byteArrayOf(0x80.toByte()))
        Asn1String.decodeFromTlv(primitive).isValid shouldBe false
        shouldThrow<Asn1Exception> { primitive.decodeToIa5String() }
    }

    "unknown validation remains non-rejecting" {
        val primitive = Asn1Primitive(Asn1Element.Tag.STRING_T61, byteArrayOf(0xe9.toByte()))
        val generic = Asn1String.decodeFromTlv(primitive)
        generic.isValid shouldBe null
        generic.value shouldBe "é"
        primitive.decodeToTeletextString().value shouldBe "é"
        Asn1String.Teletex("テスト").isValid shouldBe null
    }

    "equality and hashing do not interpret malformed content" {
        val a = Asn1String.decodeFromTlv(Asn1Primitive(Asn1Element.Tag.STRING_BMP, byteArrayOf(0)))
        val same = Asn1String.decodeFromTlv(Asn1Primitive(Asn1Element.Tag.STRING_BMP, byteArrayOf(0)))
        val other = Asn1String.decodeFromTlv(Asn1Primitive(Asn1Element.Tag.STRING_BMP, byteArrayOf(1)))
        a shouldBe same
        a.hashCode() shouldBe same.hashCode()
        (a == other) shouldBe false
    }
}
