// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(at.asitplus.awesn1.InternalAwesn1Api::class)

package at.asitplus.awesn1.io

import at.asitplus.awesn1.encoding.KxIoSink
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.io.Buffer
import kotlinx.io.readByteArray

val kxiosink_appendunsafe_rejects_zero_length by matrixSuite {
    "Appending an empty range returns zero and preserves existing bytes" {
        val buffer = Buffer()
        val sink = KxIoSink(buffer)
        sink.appendUnsafe(byteArrayOf(1, 2), 0, 2) shouldBe 2
        sink.appendUnsafe(byteArrayOf(), 0, 0) shouldBe 0
        sink.appendUnsafe(byteArrayOf(3), 1, 1) shouldBe 0
        buffer.readByteArray() shouldBe byteArrayOf(1, 2)
    }
}
