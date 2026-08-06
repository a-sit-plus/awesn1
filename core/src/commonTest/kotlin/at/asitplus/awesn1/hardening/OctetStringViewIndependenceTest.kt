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

/**
 * Deterministic, all-targets counterpart to the JVM-only `OctetStringBufferRetentionTest`.
 *
 * The parser reads OCTET STRING content as a zero-copy view into the source buffer (see `Source.readSubSource` /
 * `Asn1OctetString.ViewBacked`) to keep nested decapsulation O(input) instead of O(input²). Those views are strictly
 * parse-time: `parseOctetStrings` finalizes each raw layer into an exact-size OWNED array (`finalizeRaw`) before the
 * tree escapes. If any view survived, it would both pin the source buffer AND make the parsed tree observe later
 * mutations of that buffer.
 *
 * This asserts the mutation-observability side directly, so it needs no GC and is reliable on JVM, Native and Wasm:
 * overwrite the entire source buffer AFTER parsing; an owned (finalized) leaf is unaffected, a lingering view is not.
 * It catches the exact retention regression the JVM GC test guards, without depending on any memory-manager timing.
 */
val OctetStringViewIndependenceTest by matrixSuite {

    "a parsed raw OCTET STRING leaf does not read through to the source buffer" {
        // 0xFF.. never decodes as DER, so this stays a raw leaf that must own an exact-size copy of its content.
        val content = ByteArray(256) { 0xFF.toByte() }
        val expected = content.copyOf()
        val der = nestedOctetStrings(depth = 1, innermost = content)

        val parsed = Asn1Element.parse(der)
        parsed.shouldBeInstanceOf<Asn1OctetString>()
        (parsed is Asn1EncapsulatingOctetString) shouldBe false

        // overwrite the whole source buffer; content is read only afterwards, so a surviving view would show zeros
        der.fill(0)
        (parsed as Asn1OctetString).content shouldBe expected
    }

    "a decapsulated tree does not read through to the source buffer" {
        // outer layer encapsulates a valid inner OCTET STRING that wraps a raw 0xFF.. leaf
        val leaf = ByteArray(256) { 0xFF.toByte() }
        val expected = leaf.copyOf()
        val der = nestedOctetStrings(depth = 2, innermost = leaf)

        val parsed = Asn1Element.parse(der)
        parsed.shouldBeInstanceOf<Asn1EncapsulatingOctetString>()

        der.fill(0)
        // walk to the innermost element and confirm its bytes survived the overwrite
        var current: Asn1Element = parsed
        while (current is Asn1EncapsulatingOctetString) current = current.children.single()
        current.shouldBeInstanceOf<Asn1OctetString>()
        (current as Asn1OctetString).content shouldBe expected
        // and the whole tree still re-encodes to the original DER
        parsed.derEncoded shouldBe nestedOctetStrings(depth = 2, innermost = expected)
    }
}
