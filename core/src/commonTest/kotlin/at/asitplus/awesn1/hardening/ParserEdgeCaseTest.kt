// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.hardening

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.encoding.parseAll
import at.asitplus.awesn1.encoding.parseFirst
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain

val ParserEdgeCaseTest by matrixSuite {

    "empty input" - {
        // parse/parseFirst never return null, so they must throw — and with an Asn1Exception, not a raw
        // NoSuchElementException
        "parse throws Asn1Exception" {
            shouldThrow<Asn1Exception> { Asn1Element.parse(byteArrayOf()) }
        }
        "parseFirst throws Asn1Exception" {
            shouldThrow<Asn1Exception> { Asn1Element.parseFirst(byteArrayOf()) }
        }
        "parseAll returns an empty list" {
            Asn1Element.parseAll(byteArrayOf()) shouldBe emptyList()
        }
    }

    "forbidden universal tag 0x0F is rejected" {
        // 0F 00 : universal tag 15 (reserved) with empty content
        shouldThrow<Asn1Exception> {
            Asn1Element.parse(byteArrayOf(0x0F, 0x00))
        }.message shouldContain "0x0F"
    }

    "limit of 0" - {
        "rejects non-empty input" {
            shouldThrow<Throwable> { Asn1Element.parse(byteArrayOf(0x05, 0x00), limit = 0L) }
        }
        "rejects empty input with Asn1Exception" {
            shouldThrow<Asn1Exception> { Asn1Element.parse(byteArrayOf(), limit = 0L) }
        }
    }
}
