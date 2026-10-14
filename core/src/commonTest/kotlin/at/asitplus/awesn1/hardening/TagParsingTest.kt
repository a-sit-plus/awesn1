package at.asitplus.awesn1.at.asitplus.awesn1

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.TagClass
import at.asitplus.awesn1.copy
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

val DERtagparsing by matrixSuite {
    "single-byte factories validate and reuse tags for every identifier octet" {
        for (encoded in 0..255) {
            val number = encoded and 0x1F
            val tagClass = TagClass.entries[encoded ushr 6]
            val constructed = encoded and 0x20 != 0
            if (number == 31 || (tagClass == TagClass.UNIVERSAL && number in listOf(0, 15))) {
                shouldThrow<Asn1Exception> {
                    Asn1Element.Tag.fromEncodedSingleByte(encoded.toByte())
                }
                if (number != 31) {
                    shouldThrow<Asn1Exception> {
                        Asn1Element.Tag(number.toULong(), constructed, tagClass)
                    }
                }
            } else {
                val tag = Asn1Element.Tag.fromEncodedSingleByte(encoded.toByte())
                tag.tagValue shouldBe number.toULong()
                tag.tagClass shouldBe tagClass
                tag.isConstructed shouldBe constructed
                tag.encodedTag.toList() shouldBe listOf(encoded.toByte())
                (Asn1Element.Tag(number.toULong(), constructed, tagClass) === tag) shouldBe true
                (tag.copy() === tag) shouldBe true
                ((tag withNumber tag.tagValue) === tag) shouldBe true
                ((tag withClass tagClass) === tag) shouldBe true
            }
        }
        (Asn1Element.Tag(16uL, true) === Asn1Element.Tag.SEQUENCE) shouldBe true
        Asn1Element.Tag(31uL, false).encodedTag.toList() shouldBe listOf(0x1F.toByte(), 0x1F.toByte())
        Asn1Element.Tag(128uL, false).encodedTag.toList() shouldBe
                listOf(0x1F.toByte(), 0x81.toByte(), 0x00.toByte())
    }

    "rejects universal tag zero" - {
        listOf(
            "primitive incomplete" to "00",
            "primitive complete" to "00 00",
            "constructed incomplete" to "20",
            "constructed complete" to "20 00",
        ).asData(name = "hex", nameFn = { (name, _) -> name }) test { (_, hex) ->
            shouldThrow<Asn1Exception> {
                Asn1Element.parseFromDerHexString(hex)
            }
        }
    }

    "accepts complete non-universal tag zero" - {
        listOf(
            "application primitive" to "40 00",
            "application constructed" to "60 00",
            "context-specific primitive" to "80 00",
            "context-specific constructed" to "A0 00",
            "private primitive" to "C0 00",
            "private constructed" to "E0 00",
        ).asData(name = "hex", nameFn = { (name, _) -> name }) test { (_, hex) ->
            Asn1Element.parseFromDerHexString(hex).toDerHexString() shouldBe hex.replace(" ", "")
        }
    }

    "rejects incomplete non-universal tag zero TLVs" - {
        listOf(
            "application primitive" to "40",
            "application constructed" to "60",
            "context-specific primitive" to "80",
            "context-specific constructed" to "A0",
            "private primitive" to "C0",
            "private constructed" to "E0",
        ).asData(name = "hex", nameFn = { (name, _) -> name }) test { (_, hex) ->
            shouldThrow<Asn1Exception> {
                Asn1Element.parseFromDerHexString(hex)
            }
        }
    }

    "accepts high-tag-number 31" {
        Asn1Element.parseFromDerHexString("1F 1F 00").tag shouldBe
                Asn1Element.Tag(31uL, "1F1F".hexToByteArray(HexFormat.UpperCase))
    }

    "accepts high-tag-number 128" {
        Asn1Element.parseFromDerHexString("1F 81 00 00").tag shouldBe
                Asn1Element.Tag(128uL, "1F8100".hexToByteArray(HexFormat.UpperCase))
    }

    "rejects non-minimal high-tag-number form for tag below 31" {
        shouldThrow<Asn1Exception> {
            Asn1Element.parseFromDerHexString("1F 01 00")
        }.message shouldBe "Tag number 1 must be encoded in low-tag-number form. Encoded bytes are: 1f01"
    }

    "EOF" - {
        "no length after tag" {
            shouldThrow<Asn1Exception> {
                Asn1Element.parseFromDerHexString("1F 81 80 00")
            }.message shouldBe "Source limit exceeded: requested 1 bytes with 0 remaining (4/4 already read)"
        }

        "incomplete high-tag-number form" {
            shouldThrow<Asn1Exception> {
                Asn1Element.parseFromDerHexString("1F 81")
            }.message shouldBe "Unterminated ASN.1 unsigned varint"
        }

        "incomplete high-tag-number form with additional byte" {
            shouldThrow<Asn1Exception> {
                Asn1Element.parseFromDerHexString("1F 81 80")
            }.message shouldBe "Unterminated ASN.1 unsigned varint"
        }
    }
}
