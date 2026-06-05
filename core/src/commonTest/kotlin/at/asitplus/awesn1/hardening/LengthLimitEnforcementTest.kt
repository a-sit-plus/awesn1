package at.asitplus.awesn1.at.asitplus.awesn1

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.parse
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

val childrenLonger by matrixSuite {
    "Sequence" - {
        val sequence = Asn1.Sequence {
            +Asn1.Int(1)
        }
        val encoded = sequence.toDerHexString()

        "sanity check" {
            //encoded must be:  Sequence     containing 3 bytes         INT     1 byte long      1
            //                      30              03                  02          01           01
            encoded shouldBe "3003020101"
            Asn1Element.parseFromDerHexString(encoded) shouldBe sequence
        }

        "child longer than parent" {
            //now we replace the last three bytes with the whole parent, prefixed by (sizeOf the DER-encoded parent +3), with three padding bytes.
            //this means that the first child on its own is valid DER, but it is illegal, because the parent indicated a shorter overall
            val tampered = encoded.substring(0..<6) + "08" + encoded + "000000"

            shouldThrow<Asn1Exception> {
                Asn1Element.parseFromDerHexString(tampered)
            }.message shouldBe "ASN.1 element length for tag 2 (=02) (INTEGER) exceeds parent length: 8 > 1"
        }

        "child as long as the parent" {
            //now we replace the last three bytes with the whole parent, prefixed by (sizeOf the DER-encoded parent).
            //this means that the first child on its own is valid DER, but it is illegal, because the parent indicated a shorter overall
            val tampered = encoded.substring(0..<6) + "05" + encoded

            shouldThrow<Asn1Exception> {
                Asn1Element.parseFromDerHexString(tampered)
            }.message shouldBe "ASN.1 element length for tag 2 (=02) (INTEGER) exceeds parent length: 5 > 1"
        }
        "child one byte too long" {
            //now we replace the last three bytes with 02 (length of the following content: 2 bytes) and two zero bytes.
            //this means that the first child on its own is valid DER, but it is illegal, because the parent indicated a shorter overall
            val tampered = encoded.substring(0..<6) + "02" + "0000"

            shouldThrow<Asn1Exception> {
                Asn1Element.parseFromDerHexString(tampered)
            }.message shouldBe "ASN.1 element length for tag 2 (=02) (INTEGER) exceeds parent length: 2 > 1"
        }
    }

    // octet string behaves differently: all cases should err on trailing bytes
    "OCTET STRING Fail due to trailing bytes" - {
        val octetString = Asn1.OctetStringEncapsulating {
            +Asn1.Int(1)
        }
        val encoded = octetString.toDerHexString()

        "sanity check" {
            //encoded must be:  OCTET STRING     containing 3 bytes         INT     1 byte long      1
            //                      04                  03                  02          01           01
            encoded shouldBe "0403020101"
            Asn1Element.parseFromDerHexString(encoded) shouldBe octetString
        }

        "child longer than parent" {
            //now we replace the last three bytes with the whole parent, prefixed by (sizeOf the DER-encoded parent +3), with three padding bytes.
            //this means that the first child on its own is valid DER, but it is illegal, because the parent indicated a shorter overall
            val tampered = encoded.substring(0..<6) + "08" + encoded + "000000"

            shouldThrow<Asn1Exception> {
                Asn1Element.parseFromDerHexString(tampered)
            }.message shouldBe "Trailing bytes found after the first ASN.1 element"
        }

        "child as long as the parent" {
            //now we replace the last three bytes with the whole parent, prefixed by (sizeOf the DER-encoded parent).
            //this means that the first child on its own is valid DER, but it is illegal, because the parent indicated a shorter overall
            val tampered = encoded.substring(0..<6) + "05" + encoded

            shouldThrow<Asn1Exception> {
                Asn1Element.parseFromDerHexString(tampered)
            }.message shouldBe "Trailing bytes found after the first ASN.1 element"
        }
        "child one byte too long" {
            //now we replace the last three bytes with 02 (length of the following content: 2 bytes) and two zero bytes.
            //this means that the first child on its own is valid DER, but it is illegal, because the parent indicated a shorter overall
            val tampered = encoded.substring(0..<6) + "02" + "0000"

            shouldThrow<Asn1Exception> {
                Asn1Element.parseFromDerHexString(tampered)
            }.message shouldBe "Trailing bytes found after the first ASN.1 element"
        }

    }

    //where things get interesting is, when the illegal sequences from above are encapsulated into an octet string.
    //then, it should just return a primitive octet string and be fine
    "OCTET STRING will always parse" - {
        val octetString = Asn1.OctetStringEncapsulating {
            +Asn1.Sequence {
                +Asn1.Int(1)
            }
        }
        val encoded = octetString.content.toHexString()

        "sanity check" {
            //encoded must be:  OCTET STRING     containing 3 bytes         INT     1 byte long      1
            //                      04                  03                  02          01           01
            encoded shouldBe "3003020101"
            Asn1Element.parseFromDerHexString(encoded) shouldBe Asn1.Sequence { +Asn1.Int(1) }
        }

        "child longer than parent" {
            //now we replace the last three bytes with the whole parent, prefixed by (sizeOf the DER-encoded parent +3), with three padding bytes.
            //this means that the first child on its own is valid DER, but it is illegal, because the parent indicated a shorter overall
            val tampered = encoded.substring(0..<6) + "08" + encoded + "000000"
            Asn1Element.parse(Asn1.OctetString(tampered.hexToByteArray()).derEncoded) shouldBe Asn1.OctetString(tampered.hexToByteArray())
        }

        "child as long as the parent" {
            //now we replace the last three bytes with the whole parent, prefixed by (sizeOf the DER-encoded parent).
            //this means that the first child on its own is valid DER, but it is illegal, because the parent indicated a shorter overall
            val tampered = encoded.substring(0..<6) + "05" + encoded

            Asn1Element.parse(Asn1.OctetString(tampered.hexToByteArray()).derEncoded) shouldBe Asn1.OctetString(tampered.hexToByteArray())
        }
        "child one byte too long" {
            //now we replace the last three bytes with 02 (length of the following content: 2 bytes) and two zero bytes.
            //this means that the first child on its own is valid DER, but it is illegal, because the parent indicated a shorter overall
            val tampered = encoded.substring(0..<6) + "02" + "0000"

            Asn1Element.parse(Asn1.OctetString(tampered.hexToByteArray()).derEncoded) shouldBe Asn1.OctetString(
                tampered.hexToByteArray()
            )
        }
    }
}

val funkyLengthEncoding by matrixSuite {
    "EOF" - {
        "SEQUENCE" - {
            //SEQUENCE is special, because we lazily read, so AA BB is not decoded as a single chunk, but we try to read tag and length
            //still, we should short-circuit
            "30 03 AA BB (one byte missing bogus child)" {
                shouldThrow<Asn1Exception> {
                    Asn1Element.parseFromDerHexString("30 03 AA BB")
                }.message shouldBe "Length of ASN.1 element exceeds limit: 5 > 4"
            }

            "30 04 05 00 (NULL child declared parent content beyond input)" {
                shouldThrow<Asn1Exception> {
                    Asn1Element.parseFromDerHexString("30 04 05 00")
                }.message shouldBe "Length of ASN.1 element exceeds limit: 6 > 4"
            }

            "30 03 05 00 (one byte missing, single NULL child)" {
                shouldThrow<Asn1Exception> {
                    Asn1Element.parseFromDerHexString("30 03 05 00")
                }.message shouldBe "Length of ASN.1 element exceeds limit: 5 > 4"
            }

            "30 03 05 00 01 (one leftover octet inside parent)" {
                shouldThrow<Asn1Exception> {
                    Asn1Element.parseFromDerHexString("30 03 05 00 01")
                }.message shouldBe "Source limit exceeded: requested 1 bytes with 0 remaining (1/1 already read)"
            }
        }

        "OCTET STRING" - {
            "04 03 AA BB (one byte missing)" {
                shouldThrow<Asn1Exception> {
                    Asn1Element.parseFromDerHexString("04 03 AA BB")
                }.message shouldBe "Length of ASN.1 element exceeds limit: 5 > 4"
            }
        }

        "INT" - {
            "02 03 AA BB (one byte missing)" {
                shouldThrow<Asn1Exception> {
                    Asn1Element.parseFromDerHexString("02 03 AA BB")
                }.message shouldBe "Length of ASN.1 element exceeds limit: 5 > 4"
            }
        }
    }
}
