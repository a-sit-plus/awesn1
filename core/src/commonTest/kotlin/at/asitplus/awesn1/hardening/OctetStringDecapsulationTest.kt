// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.hardening

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1EncapsulatingOctetString
import at.asitplus.awesn1.Asn1OctetString
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.Asn1Set
import at.asitplus.awesn1.Asn1StructuralException
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.decodeToInt
import at.asitplus.awesn1.encoding.parse
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

/** Minimal DER length encoding (short form, else long form). */
private fun encodeLen(length: Int): ByteArray = when {
    length < 0x80 -> byteArrayOf(length.toByte())
    else -> {
        val octets = ArrayList<Byte>()
        var remaining = length
        while (remaining > 0) {
            octets.add(0, (remaining and 0xFF).toByte()); remaining = remaining ushr 8
        }
        byteArrayOf((0x80 or octets.size).toByte()) + octets.toByteArray()
    }
}

/** Wraps [content] in a raw OCTET STRING TLV (tag 0x04). */
private fun octet(content: ByteArray): ByteArray = byteArrayOf(0x04) + encodeLen(content.size) + content

private val int1 = Asn1.Int(1).derEncoded
private val int2 = Asn1.Int(2).derEncoded

private fun Asn1Element.asInt() = (this as Asn1Primitive).decodeToInt()

val OctetStringDecapsulationTest by matrixSuite {

    "octet string wrapping a single DER element decapsulates" {
        val der = octet(int1)
        val parsed = Asn1Element.parse(der)

        parsed.shouldBeInstanceOf<Asn1EncapsulatingOctetString>()
        parsed.children.size shouldBe 1
        parsed.children.first().asInt() shouldBe 1
        parsed.derEncoded shouldBe der
    }

    "octet string wrapping multiple DER elements decapsulates to all of them" {
        val der = octet(int1 + int2)
        val parsed = Asn1Element.parse(der)

        parsed.shouldBeInstanceOf<Asn1EncapsulatingOctetString>()
        parsed.children.map { it.asInt() } shouldBe listOf(1, 2)
        parsed.derEncoded shouldBe der
    }

    "octet string with non-DER content stays raw" {
        val garbage = byteArrayOf(0x05) // NULL tag with no length -> not valid DER
        val der = octet(garbage)
        val parsed = Asn1Element.parse(der)

        (parsed is Asn1EncapsulatingOctetString) shouldBe false
        parsed.shouldBeInstanceOf<Asn1OctetString>()
        parsed.content shouldBe garbage
        shouldThrow<Asn1StructuralException> { parsed.asEncapsulatingOctetString() }
        parsed.derEncoded shouldBe der
    }

    "empty octet string stays raw" {
        val der = octet(byteArrayOf())
        val parsed = Asn1Element.parse(der)

        (parsed is Asn1EncapsulatingOctetString) shouldBe false
        parsed.shouldBeInstanceOf<Asn1OctetString>()
        parsed.content.size shouldBe 0
        parsed.derEncoded shouldBe der
    }

    "octet string whose content has trailing bytes stays raw" {
        // a valid INT followed by a stray byte -> content does not parse cleanly -> raw
        val der = octet(int1 + byteArrayOf(0x00))
        val parsed = Asn1Element.parse(der)

        (parsed is Asn1EncapsulatingOctetString) shouldBe false
        parsed.shouldBeInstanceOf<Asn1OctetString>()
        parsed.derEncoded shouldBe der
    }

    "octet string nested one level decapsulates both layers" {
        val der = octet(octet(int1))
        val parsed = Asn1Element.parse(der)

        parsed.shouldBeInstanceOf<Asn1EncapsulatingOctetString>()
        val inner = parsed.children.single()
        inner.shouldBeInstanceOf<Asn1EncapsulatingOctetString>()
        inner.children.single().asInt() shouldBe 1
        parsed.derEncoded shouldBe der
    }

    "octet string wrapping multiple octet strings decapsulates each (SequenceOf-backed)" {
        // homogeneous content -> the node is backed by an Asn1SequenceOf; both inner octets must peel
        val der = octet(octet(int1) + octet(int2))
        val parsed = Asn1Element.parse(der)

        parsed.shouldBeInstanceOf<Asn1EncapsulatingOctetString>()
        parsed.children.size shouldBe 2
        parsed.children.forEach { it.shouldBeInstanceOf<Asn1EncapsulatingOctetString>() }
        parsed.children.map { (it as Asn1EncapsulatingOctetString).children.single().asInt() } shouldBe listOf(1, 2)
        parsed.derEncoded shouldBe der
    }

    "encapsulating octet string nested inside a SEQUENCE is decapsulated" {
        val seqDer = Asn1.Sequence { +Asn1.Int(7) }.derEncoded
        val der = Asn1.Sequence {
            +Asn1.OctetString(seqDer) // auto-encapsulates the inner SEQUENCE
            +Asn1.Int(9)
        }.derEncoded

        val parsed = Asn1Element.parse(der)
        parsed.shouldBeInstanceOf<Asn1Sequence>()
        val octetChild = parsed.children[0]
        octetChild.shouldBeInstanceOf<Asn1EncapsulatingOctetString>()
        octetChild.children.single().shouldBeInstanceOf<Asn1Sequence>()
        (octetChild.children.single() as Asn1Sequence).children.single().asInt() shouldBe 7
        parsed.children[1].asInt() shouldBe 9
        parsed.derEncoded shouldBe der
    }

    "octet string wrapping a SET of encapsulating octet strings peels through the SET" {
        // exercises the SET/SetOf adoption path: outer OCTET -> SET -> OCTET(INT) children
        val setDer = Asn1.Set {
            +Asn1.OctetString(int1)
            +Asn1.OctetString(int2)
        }.derEncoded
        val der = octet(setDer)

        val parsed = Asn1Element.parse(der)
        parsed.shouldBeInstanceOf<Asn1EncapsulatingOctetString>()
        val set = parsed.children.single()
        set.shouldBeInstanceOf<Asn1Set>()
        set.children.size shouldBe 2
        set.children.forEach { it.shouldBeInstanceOf<Asn1EncapsulatingOctetString>() }
        set.children.map { (it as Asn1EncapsulatingOctetString).children.single().asInt() }.sorted() shouldBe listOf(1, 2)
        parsed.derEncoded shouldBe der
    }

    "Asn1OctetString(bytes) auto-encapsulates valid DER and keeps non-DER raw" {
        Asn1.OctetString(int1).shouldBeInstanceOf<Asn1EncapsulatingOctetString>()

        val raw = Asn1.OctetString(byteArrayOf(0x05))
        (raw is Asn1EncapsulatingOctetString) shouldBe false
        raw.content shouldBe byteArrayOf(0x05)
    }

    "raw and encapsulating octet strings with the same content encode identically" {
        val der = octet(int1)
        val parsed = Asn1Element.parse(der) // encapsulating
        parsed.shouldBeInstanceOf<Asn1EncapsulatingOctetString>()
        // re-encoding yields the original bytes regardless of the encapsulating interpretation
        parsed.derEncoded shouldBe der
        parsed.content shouldBe int1
    }
}
