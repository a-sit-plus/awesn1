// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.hardening

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.decodeToInt
import at.asitplus.awesn1.encoding.internal.ByteArraySink
import at.asitplus.awesn1.encoding.internal.Source
import at.asitplus.awesn1.encoding.internal.readAsn1Element
import at.asitplus.awesn1.encoding.parse
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.types.shouldNotBeInstanceOf

@OptIn(InternalAwesn1Api::class)
val OctetStringLimitTest by matrixSuite {
    "depth limits stop OCTET probes before reading the next layer's content" {
        // OCTET(OCTET(INTEGER)) and OCTET(SEQUENCE(INTEGER)) both need two levels.
        listOf("04050403020105", "04053003020105").forEach { hex ->
            val bytes = hex.hexToByteArray()
            listOf(0 to 2, 1 to 4).forEach { (depth, readableUntil) ->
                val audit = OctetReadAudit(readableUntil)
                val source = AuditedOctetSource(bytes, audit)
                shouldThrow<Asn1Exception> {
                    source.readAsn1Element(bytes.size.toLong(), maxNestingDepth = depth)
                }.message shouldContain "nesting depth"
                audit.inspectedUntil shouldBe readableUntil
                audit.forbiddenReads shouldBe 0
            }
        }
    }

    "the exact depth allowance decapsulates OCTET and constructed layers" {
        val octets = "04050403020105".hexToByteArray().wrapInUnsafeSource()
            .readAsn1Element(null, maxNestingDepth = 2).first.asEncapsulatingOctetString()
        octets.element.asEncapsulatingOctetString().element.asPrimitive().decodeToInt() shouldBe 5

        val sequence = "04053003020105".hexToByteArray().wrapInUnsafeSource()
            .readAsn1Element(null, maxNestingDepth = 2).first.asEncapsulatingOctetString()
        sequence.element.asStructure().children.single().asPrimitive().decodeToInt() shouldBe 5

        "020105".hexToByteArray().wrapInUnsafeSource()
            .readAsn1Element(null, maxNestingDepth = 0).first.asPrimitive().decodeToInt() shouldBe 5
    }

    "a depth error escapes OCTET fallback before later malformed content is inspected" {
        val bytes = "040730030201051f81".hexToByteArray()
        val audit = OctetReadAudit(readableUntil = 4)
        shouldThrow<Asn1Exception> {
            AuditedOctetSource(bytes, audit).readAsn1Element(bytes.size.toLong(), maxNestingDepth = 1)
        }.message shouldContain "nesting depth"
        audit.inspectedUntil shouldBe 4
        audit.forbiddenReads shouldBe 0

        // With no depth budget, the truncated later header makes this ordinary raw OCTET content.
        val raw = Asn1Element.parse(bytes).shouldBeInstanceOf<Asn1OctetString>()
        raw.shouldNotBeInstanceOf<Asn1EncapsulatingOctetString>()
        raw.content.toHexString() shouldBe "30030201051f81"
    }

    "the byte limit rejects an OCTET before reserving or inspecting its content" {
        val bytes = "04050403020105".hexToByteArray()
        val audit = OctetReadAudit(readableUntil = 2)
        shouldThrow<Asn1Exception> {
            AuditedOctetSource(bytes, audit).readAsn1Element(bytes.size - 1L, maxNestingDepth = 2)
        }.message shouldContain "limit"
        audit.inspectedUntil shouldBe 2
        audit.forbiddenReads shouldBe 0
        audit.viewsCreated shouldBe 0
    }

    "malformed inner lengths and headers cannot borrow bytes from the next root" {
        listOf(
            "0403020205" to "020205",
            "04021f81" to "1f81",
            "04020281" to "0281",
        ).forEach { (hex, content) ->
            val root = hex.hexToByteArray()
            val bytes = root + "020109".hexToByteArray()
            val audit = OctetReadAudit(readableUntil = root.size)
            val source = AuditedOctetSource(bytes, audit)
            val (parsed, consumed) = source.readAsn1Element(bytes.size.toLong(), maxNestingDepth = 2)
            val raw = parsed.shouldBeInstanceOf<Asn1OctetString>()
            raw.shouldNotBeInstanceOf<Asn1EncapsulatingOctetString>()
            raw.content.toHexString() shouldBe content
            consumed shouldBe root.size.toLong()
            source.position shouldBe root.size
            source.exhausted() shouldBe false
            audit.inspectedUntil shouldBe root.size
            audit.forbiddenReads shouldBe 0
        }
    }
}

private class OctetReadAudit(private val readableUntil: Int) {
    var inspectedUntil = 0
        private set
    var forbiddenReads = 0
        private set
    var viewsCreated = 0

    fun read(position: Int, count: Int) {
        if (count == 0) return
        inspectedUntil = maxOf(inspectedUntil, position + count)
        if (position + count > readableUntil) {
            forbiddenReads++
            error("Read beyond the permitted OCTET prefix: ${position + count} > $readableUntil")
        }
    }
}

/** View reservation advances the parent without reading bytes; every actual read shares the audit. */
@OptIn(InternalAwesn1Api::class)
private class AuditedOctetSource(
    private val bytes: ByteArray,
    private val audit: OctetReadAudit,
    position: Int = 0,
    private val end: Int = bytes.size,
) : Source<ByteArraySink> {
    var position = position
        private set

    private fun requireAvailable(count: Int) {
        require(count >= 0 && count <= end - position) { "Read beyond source window" }
    }

    override fun readByte(): Byte {
        requireAvailable(1)
        audit.read(position, 1)
        return bytes[position++]
    }

    override fun readByteArray(nBytes: Int): ByteArray {
        requireAvailable(nBytes)
        audit.read(position, nBytes)
        return bytes.copyOfRange(position, position + nBytes).also { position += nBytes }
    }

    override fun skip(nBytes: Long) {
        require(nBytes in 0..(end - position).toLong())
        position += nBytes.toInt()
    }

    override fun exhausted() = position == end

    override fun peek() = AuditedOctetSource(bytes, audit, position, end)

    override fun readSubSource(nBytes: Int): Source<*> {
        requireAvailable(nBytes)
        audit.viewsCreated++
        return AuditedOctetSource(bytes, audit, position, position + nBytes).also { position += nBytes }
    }

    override fun transferTo(sink: ByteArraySink): Long {
        val count = end - position
        sink.write(readByteArray(count))
        return count.toLong()
    }
}
