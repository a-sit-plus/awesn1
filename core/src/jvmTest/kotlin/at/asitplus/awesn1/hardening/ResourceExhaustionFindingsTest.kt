// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(at.asitplus.awesn1.InternalAwesn1Api::class)

package at.asitplus.awesn1

import at.asitplus.awesn1.encoding.readNull
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.ints.shouldBeLessThan

val ResourceExhaustionFindings by matrixSuite {
    //disagnostics erros messages include failty inputs, but should truncate
    "rejection diagnostics are truncated" - {
        "NULL" {
            val bogusNull = Asn1Primitive(Asn1Element.Tag.NULL, ByteArray(4 * 1024 * 1024))
            (shouldThrow<Asn1Exception> { bogusNull.readNull() }.message?.length ?: 0) shouldBeLessThan 4096
        }

        "non-minimal ASN.1 REAL contents" {
            val real = ByteArray(1024 * 1024).also {
                it[0] = 0x80.toByte()
                it[2] = 0x01
            }
            (shouldThrow<Asn1Exception> { Asn1Real.decodeFromAsn1ContentBytes(real, lenient = false) }.message?.length
                ?: 0) shouldBeLessThan 4096
        }
    }
}
