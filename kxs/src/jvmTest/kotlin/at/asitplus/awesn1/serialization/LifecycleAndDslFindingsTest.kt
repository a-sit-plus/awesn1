// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(ExperimentalSerializationApi::class, ExperimentalStdlibApi::class)

package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.PemBlock
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.add
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.builtins.serializer

// Suite names preserve the original finding identifiers.
val dsl_unaryplus_numeric_operand_drop by matrixSuite {
    "Explicit serializers append numeric values to a SEQUENCE" {
        with(DER) {
            Asn1.Sequence {
                add(Int.serializer(), 5)
                add(Long.serializer(), 6L)
            }
        }.derEncoded.toHexString() shouldBe "3006020105020106"
    }

    "Inferred serializers append numeric values to a canonically sorted SET" {
        with(DER) {
            Asn1.Set {
                add(2)
                add(1)
            }
        }.derEncoded.toHexString() shouldBe "3106020101020102"
    }
}

val pem_label_fence_injection by matrixSuite {
    "A printable label produces the expected PEM block" {
        PemBlock("X", payload = byteArrayOf(1, 2, 3)).encodeToPem() shouldBe
                "-----BEGIN X-----\nAQID\n-----END X-----"
    }

    "A label containing injected PEM fences is rejected" {
        val injected = "X\n-----END X-----\n\n-----BEGIN CERTIFICATE-----\n" +
                "TUlJRkVJR0VORVJBVEVEQ0VSVElGSUNBVEU=\n-----END CERTIFICATE-----\n\n-----BEGIN Y"
        shouldThrow<IllegalArgumentException> { PemBlock(injected, payload = byteArrayOf(1, 2, 3)) }
    }
}
