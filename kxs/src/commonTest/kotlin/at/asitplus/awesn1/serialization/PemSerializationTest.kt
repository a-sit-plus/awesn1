// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)

package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.PemBlock
import at.asitplus.awesn1.PemLabelSpec
import at.asitplus.awesn1.WithPemLabel
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
private value class PemInteger(val value: Int) : WithPemLabel {
    override val pemLabel: String get() = canonicalPemLabel

    companion object : PemLabelSpec<PemInteger> {
        override val canonicalPemLabel: String = "ASN1 INTEGER"
        override val alternativePemLabels: Set<String> = setOf("INTEGER ALIAS")
    }
}

val PemSerializationTest by matrixSuite {
    "typed PEM round trip accepts a block or a string" {
        val source = PemInteger(7)
        val block = source.encodeToPemBlock()

        block.payload shouldBe byteArrayOf(2, 1, 7)
        PemInteger.decodeFromPem(block) shouldBe source
        PemInteger.decodeFromPem(source.encodeToPem()) shouldBe source
    }

    "typed PEM validates labels before decoding the payload" {
        val block = PemBlock("WRONG LABEL", payload = byteArrayOf())

        shouldThrow<IllegalArgumentException> {
            PemInteger.decodeFromPem(block)
        }.message shouldContain "WRONG LABEL"
        shouldThrow<IllegalArgumentException> {
            PemInteger.decodeFromPem(block.encodeToPem())
        }.message shouldContain "WRONG LABEL"
    }

    "typed PEM accepts alternative labels" {
        val block = PemInteger(7).encodeToPemBlock().copy(pemLabel = "INTEGER ALIAS")

        PemInteger.decodeFromPem(block) shouldBe PemInteger(7)
        PemInteger.decodeFromPem(block.encodeToPem()) shouldBe PemInteger(7)
    }

    "typed PEM reports a wrong structural type as SerializationException" {
        val block = PemBlock(PemInteger.canonicalPemLabel, payload = byteArrayOf(0x30, 3, 2, 1, 1))

        shouldThrow<SerializationException> { PemInteger.decodeFromPem(block) }
        shouldThrow<SerializationException> { PemInteger.decodeFromPem(block.encodeToPem()) }
    }

    "typed PEM string decoding honors the supplied DER configuration" {
        val pem = PemInteger(7).encodeToPem()

        PemInteger.decodeFromPem(pem, DER { maxInputLength = 3 }) shouldBe PemInteger(7)
        shouldThrow<SerializationException> {
            PemInteger.decodeFromPem(pem, DER { maxInputLength = 2 })
        }
    }

    "typed PEM string decoding rejects missing or multiple blocks" {
        shouldThrow<IllegalArgumentException> { PemInteger.decodeFromPem("no PEM here") }
        val pem = PemInteger(7).encodeToPem()
        shouldThrow<IllegalArgumentException> { PemInteger.decodeFromPem("$pem\n$pem") }
    }

    "typed PEM string decoding rejects mismatched fences" {
        val pem = PemInteger(7).encodeToPem().replace("END ASN1 INTEGER", "END WRONG LABEL")

        shouldThrow<IllegalArgumentException> { PemInteger.decodeFromPem(pem) }
    }
}
