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

/** Minimal DER length encoding (short form, else long form). */
private fun encodeLen(length: Int): ByteArray = when {
    length < 0x80 -> byteArrayOf(length.toByte())
    else -> {
        val octets = ArrayList<Byte>()
        var remaining = length
        while (remaining > 0) {
            octets.add(0, (remaining and 0xFF).toByte())
            remaining = remaining ushr 8
        }
        (byteArrayOf((0x80 or octets.size).toByte()) + octets.toByteArray())
    }
}

/**
 * Builds `depth` OCTET STRING TLVs nested inside one another, wrapping [innermost] as the deepest content.
 * Built inside-out into a single buffer (no quadratic prepends).
 */
internal fun nestedOctetStrings(depth: Int, innermost: ByteArray): ByteArray {
    val headers = ArrayList<ByteArray>(depth) // innermost layer first
    var contentSize = innermost.size
    repeat(depth) {
        val header = byteArrayOf(0x04) + encodeLen(contentSize)
        headers.add(header)
        contentSize += header.size
    }
    val out = ByteArray(contentSize)
    var pos = 0
    for (i in headers.indices.reversed()) { // outermost header first
        headers[i].copyInto(out, pos); pos += headers[i].size
    }
    innermost.copyInto(out, pos)
    return out
}

val DeepOctetStringNestingTest by matrixSuite {

    // deep enough that the former recursive OCTET STRING decoding would StackOverflow
    val depth = 20_000

    "deeply nested encapsulating OCTET STRINGs parse without StackOverflowError" {
        // innermost content is a DER NULL (05 00) -> every layer decodes as encapsulating
        val der = nestedOctetStrings(depth, byteArrayOf(0x05, 0x00))

        val parsed = Asn1Element.parse(der)

        // walk down iteratively and confirm full encapsulation depth
        var current: Asn1Element = parsed
        var seen = 0
        while (current is Asn1EncapsulatingOctetString) {
            current.children.size shouldBe 1
            current = current.children.first()
            seen++
        }
        seen shouldBe depth
        current.tag shouldBe Asn1Element.Tag.NULL // innermost NULL primitive

        // round-trips
        parsed.derEncoded shouldBe der
    }

    "malformed innermost content falls back to a raw OCTET STRING at exactly that layer" {
        // innermost content is not valid DER -> deepest octet string stays raw, all outer layers encapsulate
        val garbage = byteArrayOf(0xFF.toByte(), 0xFF.toByte())
        val der = nestedOctetStrings(depth, garbage)

        val parsed = Asn1Element.parse(der)

        var current: Asn1Element = parsed
        var encapsulated = 0
        while (current is Asn1EncapsulatingOctetString) {
            current.children.size shouldBe 1
            current = current.children.first()
            encapsulated++
        }
        // the deepest node is a raw (non-encapsulating) OCTET STRING holding the garbage bytes
        current.shouldBeInstanceOf<Asn1OctetString>()
        (current is Asn1EncapsulatingOctetString) shouldBe false
        current.content shouldBe garbage
        encapsulated shouldBe depth - 1 // deepest layer is the raw one

        parsed.derEncoded shouldBe der
    }
}
