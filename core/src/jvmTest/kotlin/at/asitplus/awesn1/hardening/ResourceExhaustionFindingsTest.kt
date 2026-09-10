// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(at.asitplus.awesn1.InternalAwesn1Api::class)

package at.asitplus.awesn1

import at.asitplus.awesn1.encoding.readNull
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json

val ResourceExhaustionFindings by matrixSuite {
    "rejection diagnostics stay bounded" {
        val bogusNull = Asn1Primitive(Asn1Element.Tag.NULL, ByteArray(4 * 1024 * 1024))
        ((shouldThrow<Asn1Exception> { bogusNull.readNull() }.message?.length ?: 0) < 4096) shouldBe true

        val real = ByteArray(1024 * 1024).also {
            it[0] = 0x80.toByte()
            it[2] = 0x01
        }
        val message = shouldThrow<Asn1Exception> {
            Asn1Real.decodeFromAsn1ContentBytes(real, lenient = false)
        }.message.orEmpty()
        (message.length < 4096) shouldBe true
    }

    "base64 fallback applies no hidden input limit" {
        val children = 100_000
        val content = ByteArray(children * 2).also { bytes -> repeat(children) { bytes[it * 2] = 0x80.toByte() } }
        val der = byteArrayOf(0x85.toByte(), 0x83.toByte(), 0x03, 0x0D, 0x40) + content
        val json = "\"${java.util.Base64.getEncoder().encodeToString(der)}\""

        Json.decodeFromString(Asn1CustomStructureFallbackBase64Serializer, json).children.size shouldBe children
    }
}
