// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.io

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import kotlinx.io.Buffer
import kotlinx.io.RawSource
import kotlinx.io.buffered

/**
 * Heavy, environment-gated regression test for the implicit collection-size limit.
 *
 * The parser accumulates children/octet slots in `ArrayList`/`ArrayDeque`, which are bounded by `Int.MAX_VALUE`
 * entries. Beyond that bound the JVM cannot grow the backing array, so the parser explicitly guards growth and
 * throws an [Asn1Exception] instead of letting an `OutOfMemoryError`/`NegativeArraySizeException` escape.
 *
 * Exercising that guard end-to-end requires feeding > 4 GiB of DER (one SEQUENCE holding > 2^31 NULL children)
 * and materializing ~2 billion child objects before the cap is hit — easily 100+ GiB of heap. That is not
 * runnable in CI, so this test is a no-op unless `AWESN1_HEAVY_TESTS` is set and the JVM is started with an
 * enormous heap (e.g. `-Xmx200g` on a machine with that much RAM). The cheap, always-run unit coverage of the
 * same guard logic lives in `core` (`LengthOverflowGuardTest.checkCollectionGrowth ...`).
 *
 * Input is generated on the fly via a [RawSource] so the 4 GiB of DER bytes are never all held in memory.
 */
val HeavyCollectionLimitTest by matrixSuite {

    "parsing a SEQUENCE with more than Int.MAX_VALUE children throws Asn1Exception, not OOM" {
        // skipped (no-op) unless explicitly enabled: needs > 4 GiB input and a 100+ GiB heap
        if (System.getenv("AWESN1_HEAVY_TESTS") != null) {
            // content = (Int.MAX_VALUE) NULL TLVs * 2 bytes each -> just over 2^31 children, past the collection cap
            val content = Int.MAX_VALUE.toLong() * 2
            val source = NullChildrenSource(content).buffered()

            // limit must allow the > 2 GiB total, otherwise the input-length guard rejects it before the cap
            shouldThrow<Asn1Exception> { Asn1Element.parse(source, limit = Long.MAX_VALUE) }
        }
    }
}

/** Emits `30 84 <4-byte len>` followed by `contentBytes` worth of repeated `05 00` (NULL) TLVs, then EOF. */
private class NullChildrenSource(private val contentBytes: Long) : RawSource {
    private val header = byteArrayOf(
        0x30,                       // SEQUENCE, constructed
        0x84.toByte(),              // long-form length, 4 octets follow
        (contentBytes ushr 24).toByte(),
        (contentBytes ushr 16).toByte(),
        (contentBytes ushr 8).toByte(),
        contentBytes.toByte(),
    )
    private var headerPos = 0
    private var contentRemaining = contentBytes
    // a chunk of many back-to-back NULL TLVs (even index -> 0x05 tag, odd index -> 0x00 length)
    private val chunk = ByteArray(1 shl 16) { if (it % 2 == 0) 0x05 else 0x00 }

    override fun readAtMostTo(sink: Buffer, byteCount: Long): Long {
        if (headerPos < header.size) {
            val n = minOf(byteCount, (header.size - headerPos).toLong()).toInt()
            sink.write(header, headerPos, headerPos + n)
            headerPos += n
            return n.toLong()
        }
        if (contentRemaining <= 0L) return -1L
        val n = minOf(byteCount, contentRemaining, chunk.size.toLong()).toInt()
        sink.write(chunk, 0, n)
        contentRemaining -= n
        return n.toLong()
    }

    override fun close() {}
}
