@file:OptIn(at.asitplus.awesn1.InternalAwesn1Api::class)

package at.asitplus.awesn1.hardening

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.internal.*
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

val Asn1ReaderTest by matrixSuite {
    "header inspection leaves payload and committed position untouched" {
        val source = InspectingSource(byteArrayOf(2, 1, 42), forbiddenFrom = 2)
        val root = Asn1Reader(source, 3)
        val value = root.next()
        value.header.contentLength shouldBe 1L
        source.committed shouldBe 0
        source.inspected shouldBe 2
    }
    "header parser reuses canonical high-tag and long-length validation" {
        val source = byteArrayOf(0x9f.toByte(), 0x81.toByte(), 0x00, 0x81.toByte(), 0x80.toByte()).wrapInUnsafeSource()
        val header = source.readAsn1Header()
        header.tag.tagValue shouldBe 128uL
        header.contentLength shouldBe 128L
        header.headerLength shouldBe 5
        header.totalLength shouldBe 133L
        source.exhausted() shouldBe true
        listOf("1f1e00", "02817f", "02800000", "1f81", "028201").forEach { hex ->
            shouldThrow<Throwable> { hex.hexToByteArray().wrapInUnsafeSource().readAsn1Header() }
        }
    }
    "nested completion reaches sibling without recursive closing" {
        val root = Asn1Reader("30053000020107".hexToByteArray().wrapInUnsafeSource(), 7)
        val children = root.next().enterContent()
        children.next().enterContent().finish()
        children.next().readPrimitive().content.toList() shouldBe listOf<Byte>(7)
        children.finish()
        root.finish()
    }
    "unfinished handles and failed operations poison the session" {
        val root = Asn1Reader(IncrementalFixtures.threeIntegers.wrapInUnsafeSource(), 11)
        root.next()
        shouldThrow<Throwable> { root.next() }
        shouldThrow<Throwable> { root.hasNext() }
    }
    "child caps reject before inspecting a surplus header" {
        val source = InspectingSource(IncrementalFixtures.fourIntegers, forbiddenFrom = 11)
        val root = Asn1Reader(source, 14)
        val children = root.next().enterContent(maxChildren = 3)
        repeat(3) { children.next().readPrimitive() }
        children.hasNext() shouldBe true
        shouldThrow<Throwable> { children.next() }
        source.inspected shouldBe 11
        source.committed shouldBe 11
    }
    "zero children and zero length contents" {
        val root = Asn1Reader("30000400".hexToByteArray().wrapInUnsafeSource(), 4)
        root.next().enterContent(maxChildren = 0).finish()
        root.next().readPrimitive().content.size shouldBe 0
        root.finish()
    }
    "boundaries and truncation reject" {
        listOf("3002020101", "30030201", "30021f81", "3003020201").forEach { hex ->
            val root = Asn1Reader(hex.hexToByteArray().wrapInUnsafeSource(), hex.length.toLong() / 2)
            shouldThrow<Throwable> {
                val children = root.next().enterContent()
                while (children.hasNext()) children.next().readPrimitive()
                children.finish()
                root.finish()
            }
        }
        shouldThrow<Throwable> { Asn1Reader(byteArrayOf(2, 1, 1).wrapInUnsafeSource(), 2).next() }
        val root = Asn1Reader(byteArrayOf(2, 1, 1).wrapInUnsafeSource(), 3, maxNestingDepth = 0)
        root.next().readPrimitive()
        root.finish()
    }
    "depth includes primitive content and materialized OCTET layers" {
        listOf("30023000", "04023000").forEach { hex ->
            val bytes = hex.hexToByteArray()
            val root = Asn1Reader(bytes.wrapInUnsafeSource(), bytes.size.toLong(), maxNestingDepth = 1)
            val children = root.next().enterContent()
            shouldThrow<Throwable> { children.next().enterContent() }
            shouldThrow<Asn1ParseLimitException> {
                bytes.wrapInUnsafeSource().readAsn1Element(bytes.size.toLong(), maxNestingDepth = 1)
            }
            val tree = bytes.wrapInUnsafeSource().readAsn1Element(bytes.size.toLong(), maxNestingDepth = 2).first
            tree.derEncoded.toList() shouldBe bytes.toList()
        }
        shouldThrow<Throwable> { Asn1Reader(InspectingSource(byteArrayOf(), 0), 0, -1) }
    }
    "materialization preserves malformed OCTET raw fallback" {
        val bytes = "0403020201".hexToByteArray()
        val root = Asn1Reader(bytes.wrapInUnsafeSource(), bytes.size.toLong(), maxNestingDepth = 2)
        root.next().readTree().derEncoded.toList() shouldBe bytes.toList()
        root.finish()
    }
    "OID lookahead leaves parent position and count unchanged" {
        val source = InspectingSource("300606012a020101".hexToByteArray(), forbiddenFrom = 5)
        val root = Asn1Reader(source, 8)
        val value = root.next()
        value.peekFirstPrimitive(Asn1Element.Tag.OID)!!.content.toList() shouldBe listOf<Byte>(42)
        source.committed shouldBe 0
        root.elementsRead shouldBe 1L
        source.inspected shouldBe 5
    }
    "wrong-tag lookahead and zero child caps never inspect payloads" {
        val source = InspectingSource("300302012a".hexToByteArray(), forbiddenFrom = 4)
        val value = Asn1Reader(source, 5).next()
        value.peekFirstPrimitive(Asn1Element.Tag.OID) shouldBe null
        source.committed shouldBe 0
        source.inspected shouldBe 4

        val capped = InspectingSource("300302012a".hexToByteArray(), forbiddenFrom = 2)
        val children = Asn1Reader(capped, 5).next().enterContent(maxChildren = 0)
        children.hasNext() shouldBe true
        shouldThrow<Throwable> { children.next() }
        capped.inspected shouldBe 2
    }
    "lookahead rejects child lengths beyond content before payload access" {
        val source = InspectingSource("300206012a".hexToByteArray(), forbiddenFrom = 4)
        val value = Asn1Reader(source, 5).next()
        shouldThrow<Throwable> { value.peekFirstPrimitive(Asn1Element.Tag.OID) }
        source.inspected shouldBe 4
        source.committed shouldBe 0
    }
    "materialization uses the smaller per-call and session depth allowance" {
        val bytes = "30023000".hexToByteArray()
        shouldThrow<Throwable> { Asn1Reader(bytes.wrapInUnsafeSource(), 4, 2).next().readTree(1) }
        shouldThrow<Throwable> { Asn1Reader(bytes.wrapInUnsafeSource(), 4, 1).next().readTree(2) }
        val root = Asn1Reader(bytes.wrapInUnsafeSource(), 4, 2)
        root.next().readTree(2).derEncoded.toList() shouldBe bytes.toList()
        root.finish()
    }
    "materialization cannot replay entered content and failure poisons children" {
        val root = Asn1Reader("300302012a".hexToByteArray().wrapInUnsafeSource(), 5)
        val value = root.next()
        val children = value.enterContent()
        shouldThrow<Throwable> { value.readTree() }
        shouldThrow<Throwable> { children.hasNext() }
    }
}
