// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1

import at.asitplus.awesn1.encoding.decodeToBmpString
import at.asitplus.awesn1.encoding.decodeToUniversalString
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

val BmpStringEncoding by matrixSuite {
    "Encoding uses UCS-2BE" {
        Asn1String.BMP("A").encodeToTlv().derEncoded.toHexString() shouldBe "1e020041"
        Asn1String.BMP("Müller").value shouldBe "Müller"
    }

    "An incomplete code unit is rejected" {
        shouldThrow<Asn1Exception> { Asn1Primitive(Asn1Element.Tag.STRING_BMP, byteArrayOf(0)).decodeToBmpString() }
    }

    "A surrogate code unit is rejected" {
        shouldThrow<Asn1Exception> {
            Asn1Primitive(Asn1Element.Tag.STRING_BMP, byteArrayOf(0xd8.toByte(), 0)).decodeToBmpString()
        }
    }

    "A supplementary character cannot be represented by BMPString" {
        shouldThrow<Asn1Exception> { Asn1String.BMP("\uD83D\uDE00") }
    }
}

val UniversalStringEncoding by matrixSuite {
    "Encoding uses UCS-4BE" {
        Asn1String.Universal("A").encodeToTlv().derEncoded.toHexString() shouldBe "1c0400000041"
    }

    "A supplementary character encodes and decodes without mutation" {
        val smile = Asn1String.Universal("\uD83D\uDE00")
        smile.encodeToTlv().derEncoded.toHexString() shouldBe "1c040001f600"
        smile.value shouldBe "\uD83D\uDE00"
    }

    "An incomplete code point is rejected" {
        shouldThrow<Asn1Exception> {
            Asn1Primitive(Asn1Element.Tag.STRING_UNIVERSAL, byteArrayOf(0)).decodeToUniversalString()
        }
    }

    "A code point above the Unicode range is rejected" {
        shouldThrow<Asn1Exception> {
            Asn1Primitive(Asn1Element.Tag.STRING_UNIVERSAL, byteArrayOf(0, 0x11, 0, 0)).decodeToUniversalString()
        }
    }

    "A surrogate code point is rejected" {
        shouldThrow<Asn1Exception> {
            Asn1Primitive(Asn1Element.Tag.STRING_UNIVERSAL, byteArrayOf(0, 0, 0xd8.toByte(), 0)).decodeToUniversalString()
        }
    }

    "A lone surrogate in a Kotlin String is rejected" {
        // Preserve the unpaired code unit even when the JS emitter normalizes string literals.
        val loneSurrogate = charArrayOf(0xd800.toChar()).concatToString()
        shouldThrow<Asn1Exception> { Asn1String.Universal(loneSurrogate) }
    }
}
