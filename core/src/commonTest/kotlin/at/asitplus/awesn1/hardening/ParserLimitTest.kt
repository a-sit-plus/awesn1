// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.hardening

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.Asn1
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
val ConstructedStructureLimitTest by matrixSuite {
    "public hex parsing rejects roots declaring more bytes than are available" {
        listOf("3003aabb", "30040500", "30030500", "0403aabb", "0203aabb").forEach { hex ->
            shouldThrow<Asn1Exception> {
                Asn1Element.parseFromDerHexString(hex)
            }.message shouldContain "exceeds limit"
        }
    }

    val tags = mapOf(
        "SEQUENCE" to "30",
        "SET" to "31",
        "explicit context tag" to "a0",
        "application structure" to "60",
        "private high tag structure" to "ff8149",
    )
    tags.forEach { (name, tag) ->
        val headerSize = tag.length / 2 + 1

        "$name accepts its exact byte budget and rejects one byte less before reading children" {
            val bytes = "${tag}03020105".hexToByteArray()
            Asn1Element.parse(bytes, limit = bytes.size.toLong()).derEncoded shouldBe bytes
            val audit = ReadAudit(readableUntil = headerSize)
            val source = AuditedSource(bytes, audit)
            shouldThrow<Asn1Exception> {
                source.readAsn1Element(bytes.size - 1L, maxNestingDepth = 1)
            }.message shouldContain "limit"
            source.position shouldBe headerSize
            audit.inspectedUntil shouldBe headerSize
            audit.forbiddenReads shouldBe 0
        }

        "$name requires a depth allowance even when empty" {
            listOf("00", "03020105").forEach { content ->
                val bytes = (tag + content).hexToByteArray()
                bytes.wrapInUnsafeSource().readAsn1Element(bytes.size.toLong(), maxNestingDepth = 1)
                    .first.derEncoded shouldBe bytes
                val audit = ReadAudit(readableUntil = headerSize)
                val source = AuditedSource(bytes, audit)
                shouldThrow<Asn1Exception> {
                    source.readAsn1Element(bytes.size.toLong(), maxNestingDepth = 0)
                }.message shouldContain "nesting depth"
                source.position shouldBe headerSize
                audit.inspectedUntil shouldBe headerSize
                audit.forbiddenReads shouldBe 0
            }
        }

        "$name cannot read malformed child headers or payloads beyond its boundary" {
            // Truncated high tag/long length, oversized payload, and a truncated header after a valid NULL.
            listOf(
                Triple("021f81", 2, 0),
                Triple("020281", 2, 0),
                Triple("03020205", 2, 0),
                Triple("03050001", 3, 2),
            ).forEach { (content, inspected, consumed) ->
                val bytes = (tag + content + "020109").hexToByteArray()
                val audit = ReadAudit(readableUntil = headerSize + inspected)
                val source = AuditedSource(bytes, audit)
                shouldThrow<Asn1Exception> {
                    source.readAsn1Element(bytes.size.toLong(), maxNestingDepth = 1)
                }
                source.position shouldBe headerSize + consumed
                audit.inspectedUntil shouldBe headerSize + inspected
                audit.forbiddenReads shouldBe 0
                shouldThrow<Asn1Exception> { Asn1Element.parseFromDerHexString(tag + content) }
            }
        }

        "$name counts sibling structures by depth rather than their total number" {
            val bytes = "${tag}0a30030201053103020106".hexToByteArray()
            bytes.wrapInUnsafeSource().readAsn1Element(bytes.size.toLong(), maxNestingDepth = 2)
                .first.derEncoded shouldBe bytes
        }

        "$name preserves the depth count when an OCTET encapsulates another $name" {
            val inner = "${tag}03020105"
            val octet = "04${(inner.length / 2).toString(16).padStart(2, '0')}$inner"
            val bytes = "$tag${(octet.length / 2).toString(16).padStart(2, '0')}$octet".hexToByteArray()
            listOf(1 to headerSize + 2, 2 to 2 * headerSize + 2).forEach { (depth, readableUntil) ->
                val audit = ReadAudit(readableUntil)
                shouldThrow<Asn1Exception> {
                    AuditedSource(bytes, audit).readAsn1Element(bytes.size.toLong(), maxNestingDepth = depth)
                }.message shouldContain "nesting depth"
                audit.inspectedUntil shouldBe readableUntil
                audit.forbiddenReads shouldBe 0
            }
            val parsed = bytes.wrapInUnsafeSource().readAsn1Element(bytes.size.toLong(), maxNestingDepth = 3).first
            parsed.derEncoded shouldBe bytes
            parsed.asStructure().children.single().asEncapsulatingOctetString().element
                .asStructure().children.single().asPrimitive().decodeToInt() shouldBe 5
        }

        tags.forEach { (innerName, innerTag) ->
            "$name containing $innerName shares one depth budget and stops before the leaf" {
                val inner = "${innerTag}03020105"
                val bytes = "$tag${(inner.length / 2).toString(16).padStart(2, '0')}$inner".hexToByteArray()
                val readableUntil = headerSize + innerTag.length / 2 + 1
                val audit = ReadAudit(readableUntil)
                val source = AuditedSource(bytes, audit)
                shouldThrow<Asn1Exception> {
                    source.readAsn1Element(bytes.size.toLong(), maxNestingDepth = 1)
                }.message shouldContain "nesting depth"
                source.position shouldBe readableUntil
                audit.inspectedUntil shouldBe readableUntil
                audit.forbiddenReads shouldBe 0

                val complete = bytes.wrapInUnsafeSource()
                val (parsed, consumed) = complete.readAsn1Element(bytes.size.toLong(), maxNestingDepth = 2)
                parsed.derEncoded shouldBe bytes
                consumed shouldBe bytes.size.toLong()
                complete.exhausted() shouldBe true
            }
        }
    }
}

@OptIn(InternalAwesn1Api::class)
val OctetStringLimitTest by matrixSuite {
    "OCTET probes accept the exact depth allowance and stop before disallowed content" {
        // OCTET(OCTET(INTEGER)) and OCTET(SEQUENCE(INTEGER)) both need two levels.
        listOf("04050403020105", "04053003020105").forEach { hex ->
            val bytes = hex.hexToByteArray()
            listOf(0 to 2, 1 to 4).forEach { (depth, readableUntil) ->
                val audit = ReadAudit(readableUntil)
                val source = AuditedSource(bytes, audit)
                shouldThrow<Asn1Exception> {
                    source.readAsn1Element(bytes.size.toLong(), maxNestingDepth = depth)
                }.message shouldContain "nesting depth"
                audit.inspectedUntil shouldBe readableUntil
                audit.forbiddenReads shouldBe 0
            }
            val parsed = bytes.wrapInUnsafeSource().readAsn1Element(null, maxNestingDepth = 2)
                .first.asEncapsulatingOctetString()
            val leaf = when (val inner = parsed.element) {
                is Asn1EncapsulatingOctetString -> inner.element
                else -> inner.asStructure().children.single()
            }
            leaf.asPrimitive().decodeToInt() shouldBe 5
            parsed.derEncoded shouldBe bytes
        }
    }

    "a primitive needs no nesting allowance" {
        "020105".hexToByteArray().wrapInUnsafeSource()
            .readAsn1Element(null, maxNestingDepth = 0).first.asPrimitive().decodeToInt() shouldBe 5
    }

    "oversized children fail directly, remain raw when encapsulated, and cannot hide trailing bytes" {
        listOf("300302083003020101000000", "300302053003020101", "300302020000").forEach { hex ->
            shouldThrow<Asn1Exception> {
                Asn1Element.parseFromDerHexString(hex)
            }.message shouldContain "exceeds parent length"

            val raw = Asn1.OctetString(hex.hexToByteArray())
            Asn1Element.parse(raw.derEncoded) shouldBe raw

            shouldThrow<Asn1Exception> {
                Asn1Element.parseFromDerHexString("04" + hex.drop(2))
            }.message shouldBe "Trailing bytes found after the first ASN.1 element"
        }
    }

    "a depth error escapes OCTET fallback before later malformed content is inspected" {
        val bytes = "040730030201051f81".hexToByteArray()
        val audit = ReadAudit(readableUntil = 4)
        shouldThrow<Asn1Exception> {
            AuditedSource(bytes, audit).readAsn1Element(bytes.size.toLong(), maxNestingDepth = 1)
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
        val audit = ReadAudit(readableUntil = 2)
        shouldThrow<Asn1Exception> {
            AuditedSource(bytes, audit).readAsn1Element(bytes.size - 1L, maxNestingDepth = 2)
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
            val audit = ReadAudit(readableUntil = root.size)
            val source = AuditedSource(bytes, audit)
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

private class ReadAudit(private val readableUntil: Int) {
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
            error("Read beyond the permitted parser prefix: ${position + count} > $readableUntil")
        }
    }
}

/** View reservation advances the parent without reading bytes; every actual read shares the audit. */
@OptIn(InternalAwesn1Api::class)
private class AuditedSource(
    private val bytes: ByteArray,
    private val audit: ReadAudit,
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

    override fun peek() = AuditedSource(bytes, audit, position, end)

    override fun readSubSource(nBytes: Int): Source<*> {
        requireAvailable(nBytes)
        audit.viewsCreated++
        return AuditedSource(bytes, audit, position, position + nBytes).also { position += nBytes }
    }

    override fun transferTo(sink: ByteArraySink): Long {
        val count = end - position
        sink.write(readByteArray(count))
        return count.toLong()
    }
}
