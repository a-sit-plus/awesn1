// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.hardening

import at.asitplus.awesn1.Asn1CustomStructure
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1ExplicitlyTagged
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.Asn1Structure
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.parse
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.kotest.matchers.types.shouldBeInstanceOf

/** Minimal DER length encoding (short form, else long form). */
private fun encodeLen(length: Int): ByteArray = when {
    length < 0x80 -> byteArrayOf(length.toByte())
    else -> {
        val octets = ArrayList<Byte>()
        var remaining = length
        while (remaining > 0) {
            octets.add(0, (remaining and 0xFF).toByte()); remaining = remaining ushr 8
        }
        byteArrayOf((0x80 or octets.size).toByte()) + octets.toByteArray()
    }
}

/**
 * Builds `depth` constructed TLVs nested inside one another, wrapping [innermost] as the deepest content.
 * [tagFor] supplies the identifier octet for each layer (index 0 = innermost). Built inside-out into a single
 * buffer (no quadratic prepends).
 */
internal fun nestedConstructed(depth: Int, innermost: ByteArray, tagFor: (Int) -> Byte): ByteArray {
    val headers = ArrayList<ByteArray>(depth) // innermost layer first
    var contentSize = innermost.size
    repeat(depth) { layer ->
        val header = byteArrayOf(tagFor(layer)) + encodeLen(contentSize)
        headers.add(header)
        contentSize += header.size
    }
    val out = ByteArray(contentSize)
    var pos = 0
    for (i in headers.indices.reversed()) { headers[i].copyInto(out, pos); pos += headers[i].size }
    innermost.copyInto(out, pos)
    return out
}

private val NULL = byteArrayOf(0x05, 0x00)

/** Walks straight down a single-child structural chain, returning (#structures descended, innermost leaf). */
internal fun descend(root: Asn1Element): Pair<Int, Asn1Element> {
    var current = root
    var seen = 0
    while (current is Asn1Structure) {
        current.children.size shouldBe 1
        current = current.children.single()
        seen++
    }
    return seen to current
}

val DeepStructuralNestingTest by matrixSuite {

    // deep enough that the former recursive (readAsn1Element/doParseExactly) parser — and the interim
    // BoundedSource-per-frame chaining — would StackOverflow. This is the axis the iterative frame-stack parser
    // exists to flatten: structural nesting, not OCTET STRINGs.
    //
    // NOTE: these assert *parsing* stack-safety only (the iterative descent below never forces the recursive
    // contentLength/derEncoded computation). Encoding a 50k-deep tree is a separate recursion axis; structural
    // round-trip is covered at a safe depth by the last case.
    val depth = 50_000

    "deeply nested SEQUENCEs parse iteratively without StackOverflowError" {
        val der = nestedConstructed(depth, NULL) { 0x30 } // 0x30 = SEQUENCE
        var current: Asn1Element = Asn1Element.parse(der)
        var seen = 0
        while (current is Asn1Structure) {
            current.shouldBeInstanceOf<Asn1Sequence>()
            current.children.size shouldBe 1
            current = current.children.single()
            seen++
        }
        seen shouldBe depth
        current.tag shouldBe Asn1Element.Tag.NULL
    }

    "deeply nested explicit context tags parse iteratively without StackOverflowError" {
        val der = nestedConstructed(depth, NULL) { 0xA0.toByte() } // context [0], constructed -> explicit
        var current: Asn1Element = Asn1Element.parse(der)
        var seen = 0
        while (current is Asn1Structure) {
            current.shouldBeInstanceOf<Asn1ExplicitlyTagged>()
            current.children.size shouldBe 1
            current = current.children.single()
            seen++
        }
        seen shouldBe depth
        current.tag shouldBe Asn1Element.Tag.NULL
    }

    "deeply nested implicit custom-constructed structures parse iteratively without StackOverflowError" {
        val der = nestedConstructed(depth, NULL) { 0x60 } // application [0], constructed -> custom structure
        var current: Asn1Element = Asn1Element.parse(der)
        var seen = 0
        while (current is Asn1Structure) {
            current.shouldBeInstanceOf<Asn1CustomStructure>()
            current.children.size shouldBe 1
            current = current.children.single()
            seen++
        }
        seen shouldBe depth
        current.tag shouldBe Asn1Element.Tag.NULL
    }

    "deeply nested mix of SEQUENCE, explicit and custom structures parses without StackOverflowError" {
        // alternate the three constructed kinds per layer to stress the frame stack with mixed frame types
        val tags = byteArrayOf(0x30, 0xA0.toByte(), 0x60)
        val der = nestedConstructed(depth, NULL) { layer -> tags[layer % tags.size] }
        val (seen, innermost) = descend(Asn1Element.parse(der))
        seen shouldBe depth
        innermost.tag shouldBe Asn1Element.Tag.NULL
    }

    "deeply nested structures encode and stringify iteratively, truncating bounded output" {
        val tags = byteArrayOf(0x30, 0xA0.toByte(), 0x60)
        val der = nestedConstructed(depth, NULL) { layer -> tags[layer % tags.size] }
        val parsed = Asn1Element.parse(der)

        parsed.derEncoded shouldBe der   // round-trips, stack-safe

        // toString / prettyPrint are stack-safe AND truncate (JVM String/StringBuilder are Int-bound), so even a
        // 50k-deep tree renders to a bounded, terminated string instead of OOMing
        val s = parsed.toString()
        s shouldContain "output truncated"
        (s.length < (1 shl 21)) shouldBe true

        val p = parsed.prettyPrint()
        p shouldContain "output truncated"
        (p.length < (1 shl 21)) shouldBe true
    }

    "toString(limit) and prettyPrint(limit) honor an explicit character limit" {
        val parsed = Asn1Element.parse(nestedConstructed(20, NULL) { 0x30 }) // small: default render is complete

        parsed.toString() shouldNotContain "output truncated"

        val s = parsed.toString(limit = 30)
        s shouldContain "output truncated"
        (s.length < 60) shouldBe true

        parsed.prettyPrint(limit = 30) shouldContain "output truncated"
    }

    "a huge primitive's string render is bounded, not materialized in full" {
        val raw = ByteArray(8 * 1024 * 1024) // 8 MiB; first byte 0x00 -> not valid DER -> stays a raw OCTET STRING
        val s = Asn1.OctetString(raw).toString()
        (s.length < (1 shl 21)) shouldBe true
        s shouldContain "bytes)" // the per-leaf content-truncation marker "…(N bytes)"
    }

    "deeply nested SETs round-trip and stringify without StackOverflowError" {
        // SET toString forces isActuallySorted -> the DER comparator, which used to recurse; now stack-safe
        val der = nestedConstructed(depth, NULL) { 0x31 } // 0x31 = SET
        val parsed = Asn1Element.parse(der)

        parsed.derEncoded shouldBe der
        (parsed.toString().length > 0) shouldBe true   // exercises isActuallySorted/comparator iteratively
    }
}
