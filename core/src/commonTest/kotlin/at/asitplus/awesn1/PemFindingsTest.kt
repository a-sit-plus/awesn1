// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.types.shouldBeInstanceOf

val PemFindingsTest by matrixSuite {
    "pem_label_fence_injection" {
        PemBlock("X", payload = byteArrayOf(1, 2, 3)).encodeToPem().shouldBeInstanceOf<String>()

        val injected = "X\n-----END X-----\n\n-----BEGIN CERTIFICATE-----\n" +
                "TUlJRkVJR0VORVJBVEVEQ0VSVElGSUNBVEU=\n-----END CERTIFICATE-----\n\n-----BEGIN Y"
        shouldThrow<IllegalArgumentException> { PemBlock(injected, payload = byteArrayOf(1, 2, 3)) }
    }
}
