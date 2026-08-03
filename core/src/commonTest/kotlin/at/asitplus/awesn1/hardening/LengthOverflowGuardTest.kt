// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.hardening

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.encodeLength
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.plusExact
import at.asitplus.awesn1.toNonnegativeIntChecked
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

val LengthOverflowGuardTest by matrixSuite {

    "Long.encodeLength matches Int.encodeLength for in-range values" {
        listOf(0, 1, 127, 128, 255, 256, 65535, 65536, 1_000_000, Int.MAX_VALUE).forEach { v ->
            v.toLong().encodeLength().toList() shouldBe v.encodeLength().toList()
        }
    }

    "Long.encodeLength encodes lengths beyond Int range" {
        // 2^32 -> long form, 5 magnitude octets (0x85, 01 00 00 00 00)
        (1L shl 32).encodeLength().toList() shouldBe
                byteArrayOf(0x85.toByte(), 0x01, 0x00, 0x00, 0x00, 0x00).toList()
        // 2^40 -> long form, 6 magnitude octets (0x86, 01 00 00 00 00 00)
        (1L shl 40).encodeLength().toList() shouldBe
                byteArrayOf(0x86.toByte(), 0x01, 0x00, 0x00, 0x00, 0x00, 0x00).toList()
    }

    "toNonnegativeIntChecked returns in range and throws otherwise" {
        0L.toNonnegativeIntChecked() shouldBe 0
        Int.MAX_VALUE.toLong().toNonnegativeIntChecked() shouldBe Int.MAX_VALUE
        shouldThrow<Asn1Exception> { (Int.MAX_VALUE.toLong() + 1).toNonnegativeIntChecked("content length") }
        shouldThrow<Asn1Exception> { (-1L).toNonnegativeIntChecked() }
    }

    "plusExact throws on Long overflow" {
        (Long.MAX_VALUE - 1).plusExact(1) shouldBe Long.MAX_VALUE
        shouldThrow<Asn1Exception> { Long.MAX_VALUE.plusExact(1) }
        shouldThrow<Asn1Exception> { (Long.MAX_VALUE - 5).plusExact(10) }
    }

    "Long length properties agree with the guarded Int views for ordinary elements" {
        val der = Asn1.Sequence {
            +Asn1.Int(1)
            +Asn1.OctetString(byteArrayOf(1, 2, 3, 4, 5))
        }.derEncoded
        val parsed = Asn1Element.parse(der)

        parsed.contentLengthLong shouldBe parsed.contentLength.toLong()
        parsed.overallLengthLong shouldBe parsed.overallLength.toLong()
        parsed.overallLengthLong shouldBe der.size.toLong()
        parsed.derEncoded shouldBe der
    }
}
