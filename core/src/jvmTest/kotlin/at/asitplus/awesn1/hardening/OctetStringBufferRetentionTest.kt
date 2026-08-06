// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.hardening

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1EncapsulatingOctetString
import at.asitplus.awesn1.Asn1OctetString
import at.asitplus.awesn1.encoding.parse
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import java.lang.ref.WeakReference

/**
 * Regression guard for OCTET STRING decapsulation retention (JVM-only; relies on [System.gc]).
 *
 * The parser reads OCTET STRING content as a zero-copy view into the source buffer (see `Source.readSubSource` /
 * `Asn1OctetString.ViewBacked`) so that nested decapsulation stays O(input) instead of O(input²). Those views are
 * strictly parse-time: `parseOctetStrings` finalizes every one before the tree is handed out — encapsulating layers
 * retain no bytes, and a layer that stays raw is copied into an exact-size owned array (`finalizeRaw`). Consequently
 * a parsed tree must NOT keep the (potentially far larger) input buffer alive through a lingering view.
 *
 * Each test builds and parses inside a helper so the ONLY strong reference to the input array is whatever the parsed
 * tree itself holds; a [WeakReference] to the input must then clear under GC. Were a view still pinning the buffer,
 * it never would and the test would fail.
 */
val OctetStringBufferRetentionTest by matrixSuite {

    // Best-effort reclaim probe: succeeds as soon as the referent is collected. `keepAlive` is touched afterwards so
    // the parsed tree is provably live across the whole loop — i.e. we test "does the TREE pin the input", not "did
    // the input simply go out of scope".
    fun assertCollected(ref: WeakReference<*>, keepAlive: Any) {
        var cleared = false
        repeat(50) {
            if (ref.get() == null) { cleared = true; return@repeat }
            System.gc()
            Thread.sleep(10)
        }
        keepAlive.hashCode() // keep the tree strongly reachable until here
        cleared shouldBe true
    }

    "a raw OCTET STRING leaf does not pin the larger source buffer" {
        // ~1 MB of 0xFF is not valid DER -> the octet string stays raw and must own an exact-size copy, not a view.
        fun parseRawLeaf(): Pair<Asn1Element, WeakReference<ByteArray>> {
            val der = nestedOctetStrings(depth = 1, innermost = ByteArray(1_000_000) { 0xFF.toByte() })
            return Asn1Element.parse(der) to WeakReference(der)
        }

        val (parsed, inputRef) = parseRawLeaf()
        parsed.shouldBeInstanceOf<Asn1OctetString>()
        (parsed is Asn1EncapsulatingOctetString) shouldBe false // genuinely raw
        parsed.contentLengthLong shouldBe 1_000_000L
        assertCollected(inputRef, keepAlive = parsed)
    }

    "deeply nested encapsulation retains none of the source buffer" {
        // Every layer decodes (innermost is a DER NULL), so all octet layers become encapsulating (no retained bytes)
        // and the sole leaf is a 2-byte primitive. Nothing may keep the ~1 MB input alive.
        fun parseAllEncapsulating(): Pair<Asn1Element, WeakReference<ByteArray>> {
            val der = nestedOctetStrings(depth = 250_000, innermost = byteArrayOf(0x05, 0x00))
            return Asn1Element.parse(der) to WeakReference(der)
        }

        val (parsed, inputRef) = parseAllEncapsulating()
        parsed.shouldBeInstanceOf<Asn1EncapsulatingOctetString>()
        assertCollected(inputRef, keepAlive = parsed)
    }
}
