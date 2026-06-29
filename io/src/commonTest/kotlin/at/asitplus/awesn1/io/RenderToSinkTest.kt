// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.io

import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlinx.io.Buffer
import kotlinx.io.readByteArray

val RenderToSinkTest by matrixSuite {

    val element = Asn1.Sequence {
        +Asn1.Int(1)
        +Asn1.OctetString(byteArrayOf(1, 2, 3))
        +Asn1.Bool(true)
    }

    "toString(sink) writes the same as the in-memory toString()" {
        val buffer = Buffer()
        element.toString(buffer)
        buffer.readByteArray().decodeToString() shouldBe element.toString()
    }

    "prettyPrint(sink) writes the same as the in-memory prettyPrint()" {
        val buffer = Buffer()
        element.prettyPrint(buffer)
        buffer.readByteArray().decodeToString() shouldBe element.prettyPrint()
    }

    "toString(sink, limit) truncates at the given limit" {
        val buffer = Buffer()
        element.toString(buffer, limit = 25)
        val rendered = buffer.readByteArray().decodeToString()
        rendered shouldContain "output truncated"
        (rendered.length < 60) shouldBe true
    }
}
