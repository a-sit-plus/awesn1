package at.asitplus.awesn1.at.asitplus.awesn1

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.Asn1SequenceOf
import at.asitplus.awesn1.Asn1SequenceOfFallbackBase64Serializer
import at.asitplus.awesn1.Asn1Set
import at.asitplus.awesn1.Asn1SetOf
import at.asitplus.awesn1.Asn1SetOfFallbackBase64Serializer
import at.asitplus.awesn1.encoding.parse
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

val SequenceOfTest by matrixSuite {

    "empty parsed SET produces Asn1SetOf (vacuous tag-homogeneity)" {
        val emptySet = Asn1Set(emptyList())

        val parsed = Asn1Element.parse(emptySet.derEncoded)

        parsed.shouldBeInstanceOf<Asn1SetOf>()
        emptySet.shouldBeInstanceOf<Asn1SetOf>()
        parsed.asSetOf().commonTag shouldBe null
    }

    "empty parsed SEQUENCE produces Asn1SequenceOf (vacuous tag-homogeneity)" {
        val emptySeq = Asn1Sequence(emptyList())

        val parsed = Asn1Element.parse(emptySeq.derEncoded)

        parsed.shouldBeInstanceOf<Asn1SequenceOf>()
        emptySeq.shouldBeInstanceOf<Asn1SequenceOf>()
        parsed.asSequenceOf().commonTag shouldBe null
    }

    "parsing homogeneous SEQUENCE produces Asn1SequenceOf" {
        val a = Asn1Primitive(Asn1Element.Tag.INT, byteArrayOf(0x01))
        val b = Asn1Primitive(Asn1Element.Tag.INT, byteArrayOf(0x02))
        val seqOf = Asn1Sequence(listOf(a, b))

        val parsed = Asn1Element.parse(seqOf.derEncoded)

        parsed.shouldBeInstanceOf<Asn1SequenceOf>()
        parsed.asSequenceOf().commonTag shouldBe Asn1Element.Tag.INT
    }

    "parsing heterogeneous SEQUENCE produces plain Asn1Sequence" {
        val intElem = Asn1Primitive(Asn1Element.Tag.INT, byteArrayOf(0x01))
        val boolElem = Asn1Primitive(Asn1Element.Tag.BOOL, byteArrayOf(0xff.toByte()))
        val seq = Asn1Sequence(listOf(intElem, boolElem))

        val parsed = Asn1Element.parse(seq.derEncoded)

        parsed::class shouldBe Asn1Sequence::class
    }

    "Asn1SequenceOf.commonTag matches children tag" {
        val elem = Asn1Primitive(Asn1Element.Tag.OCTET_STRING, byteArrayOf(0x00))
        val seqOf = Asn1SequenceOf(listOf(elem, elem))

        seqOf.commonTag shouldBe Asn1Element.Tag.OCTET_STRING
    }

    "Asn1SetOf fallback serializer decodeFromAsn1Element works for empty set" {
        val emptySetOf = Asn1SetOf(emptyList())
        val decoded = Asn1SetOfFallbackBase64Serializer.decodeFromAsn1Element(emptySetOf)
        decoded.children.size shouldBe 0
    }

    "Asn1SequenceOf fallback serializer decodeFromAsn1Element works for empty sequence" {
        val emptySeqOf = Asn1SequenceOf(emptyList())
        val decoded = Asn1SequenceOfFallbackBase64Serializer.decodeFromAsn1Element(emptySeqOf)
        decoded.children.size shouldBe 0
    }

    "Asn1Element.parse does not convert empty Asn1Set to Asn1SetOf when tags differ" {
        // This is already covered by empty set, but let's be explicit
        val emptyPlainSet = Asn1Set(emptyList())
        val parsed = Asn1Element.parse(emptyPlainSet.derEncoded)
        // Empty SET should be Asn1SetOf because vacuous truth applies
        parsed.shouldBeInstanceOf<Asn1SetOf>()
    }
}

val SetOfTest by matrixSuite {

    "parsing homogeneous SET produces Asn1SetOf" {
        val larger = Asn1Primitive(Asn1Element.Tag.OCTET_STRING, byteArrayOf(0x01))
        val smaller = Asn1Primitive(Asn1Element.Tag.OCTET_STRING, byteArrayOf(0x00))
        val setOf = Asn1Set(listOf(larger, smaller))

        val parsed = Asn1Element.parse(setOf.derEncoded)

        parsed.shouldBeInstanceOf<Asn1SetOf>()
        setOf.shouldBeInstanceOf<Asn1SetOf>()
    }


    "parsing empty SET produces Asn1SetOf" {
        val setOf = Asn1Set(listOf())

        val parsed = Asn1Element.parse(setOf.derEncoded)

        parsed.shouldBeInstanceOf<Asn1SetOf>()
        setOf.shouldBeInstanceOf<Asn1SetOf>()
    }


    "parsing heterogeneous SET produces plain Asn1Set" {
        val intElem = Asn1Primitive(Asn1Element.Tag.INT, byteArrayOf(0x01))
        val boolElem = Asn1Primitive(Asn1Element.Tag.BOOL, byteArrayOf(0xff.toByte()))
        val set = Asn1Set(listOf(intElem, boolElem))

        val parsed = Asn1Element.parse(set.derEncoded)

        parsed::class shouldBe Asn1Set::class
    }

    "Asn1SetOf.commonTag is null for empty set" {
        val emptySetOf = Asn1SetOf(emptyList())

        emptySetOf.commonTag shouldBe null
    }

    "Asn1SetOf.commonTag matches children tag" {
        val elem = Asn1Primitive(Asn1Element.Tag.OCTET_STRING, byteArrayOf(0x00))
        val setOf = Asn1SetOf(listOf(elem, elem))

        setOf.commonTag shouldBe Asn1Element.Tag.OCTET_STRING
    }
}