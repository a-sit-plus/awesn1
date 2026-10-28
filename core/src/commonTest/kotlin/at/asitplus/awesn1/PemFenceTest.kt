// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

val PemHeaderFenceValidation by matrixSuite {
    "A clean header preserves the full PEM block on round-trip" {
        val block = PemBlock("CERTIFICATE", listOf(PemHeader("Comment", "clean")), ByteArray(30) { it.toByte() })
        PemBlock.decodeAllFromPem(block.encodeToPem()).single() shouldBe block
    }

    for (fence in listOf("-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----")) {
        "A header name containing $fence is rejected" {
            shouldThrow<IllegalArgumentException> { PemHeader("Comment\n$fence", "clean") }
        }

        "A header value containing $fence is rejected" {
            shouldThrow<IllegalArgumentException> { PemHeader("Comment", "hi\n$fence") }
        }
    }
}
