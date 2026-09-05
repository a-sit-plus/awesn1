// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0


package at.asitplus.awesn1

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json

@OptIn(ExperimentalStdlibApi::class)
val BitVectorHardening by matrixSuite {
    /*
     * bitset_boxed_byte_retained_amplification
     *
     * BUG: BitSet stores one BOXED Byte reference per octet in a MutableList<Byte> instead of
     * packing bits into primitive storage. Asn1BitString.toBitSet() therefore RETAINS ~4-8x
     * the attacker-controlled BIT STRING content for the whole lifetime of the BitSet — long
     * after the input bytes and the parsed element have been released.
     *
     * TRIGGER: 4 MiB of BIT STRING content; measure the heap still held once only the BitSet
     * is reachable. A packed representation retains ~1x.
     */
    "bitset_boxed_byte_retained_amplification" {
        val contentSize = 4 * 1024 * 1024
        val bitString = Asn1BitString(ByteArray(contentSize) { 0xFF.toByte() })
        var bitSet: BitSet? = null
        val allocated = allocatedBytes { bitSet = bitString.toBitSet() }
        // Keep the BitSet reachable across the measurement.
        bitSet!!.toLsb0ByteArray().size shouldNotBe -1
        // A packed representation costs ~1x the content; boxed Bytes cost 4-8x.
        (allocated < contentSize.toLong() * 3) shouldBe true
    }

    /*
     * bitset_deserialize_quadratic_zero_run_dos_v3
     *
     * BUG: BitSet.set did not amortise buffer maintenance - every cleared-bit write extended
     * the MutableList element-by-element and then compact() physically trimmed every trailing
     * zero byte again, so growing and shrinking across a byte boundary was Theta(n^2).
     *
     * TRIGGER (B1): the finding's stated payload, a "<padding>:<base64>" BIT STRING with a long
     * zero run, decoded and converted with toBitSet(). Control (A): the same length of DENSE
     * content, so the cost is the zero run and not the size.
     *
     * TRIGGER (B2): the grow/shrink oscillation itself - repeatedly setting and clearing one
     * high bit. Under the old storage each iteration grew the buffer one boxed byte at a time
     * and then compacted all of it away again; it must now be O(1) per iteration.
     */
    "bitset_deserialize_quadratic_zero_run_dos_v3" {
        val n = 16384

        // Control (A): dense content of the same size is fast.
        val denseMillis = measureMillis {
            Json.decodeFromString(Asn1BitString.Companion, "\"0:" + base64(ByteArray(n) { 0xFF.toByte() }) + "\"")
                .toBitSet()
        }
        (denseMillis < 2_000) shouldBe true

        // Fault (B1): a zero run of the same size must not be quadratically more expensive.
        val zeroRunMillis = measureMillis {
            Json.decodeFromString(Asn1BitString.Companion, "\"0:" + base64(ByteArray(n).also { it[n - 1] = 1 }) + "\"")
                .toBitSet()
        }
        (zeroRunMillis < 2_000) shouldBe true

        // Fault (B2): setting and clearing the same high bit must not re-grow and re-trim the
        // whole backing array on every iteration.
        val oscillationMillis = measureMillis {
            val bits = BitSet()
            repeat(200) {
                bits[8_000_000L] = true
                bits[8_000_000L] = false
            }
        }
        (oscillationMillis < 2_000) shouldBe true
    }

    /*
     * bitset_fromstring_quadratic_cpu_dos
     *
     * BUG: BitSet.fromString calls set() per character, and every set(index, false)
     * unconditionally triggers the O(buffer) compact() scan-and-trim, so parsing an
     * unbounded bit string is quadratic in its length.
     *
     * TRIGGER: "1" followed by 99_999 zeros. Control: 1_000_000 '1' characters — twenty times
     * longer — parses in milliseconds because the set(true) path never compacts.
     */
    "bitset_fromstring_quadratic_cpu_dos" {
        // Control (A): the all-ones path is linear.
        (measureMillis { BitSet.fromLogicalBitString("1".repeat(1_000_000)) } < 2_000) shouldBe true

        // Fault (B): a far shorter zero run costs seconds.
        (measureMillis { BitSet.fromLogicalBitString("1" + "0".repeat(99_999)) } < 2_000) shouldBe true
    }

    /*
     * bitset_negative_set_silent_noop
     *
     * BUG: BitSet.set never checks the sign of the index, and its delegated guard
     * getByteIndex() validates only the TRUNCATING quotient index/8 — which is 0 for -7..-1.
     * Those writes therefore silently no-op instead of throwing, while every read path
     * (get / nextSetBit / flip) correctly throws for the same indices.
     *
     * TRIGGER: set(-1, true) must not return normally. Control: get(-1) does throw.
     */
    "bitset_negative_set_silent_noop" {
        val bits = BitSet()

        // Control (A): the read path rejects negative indices.
        shouldThrow<IndexOutOfBoundsException> { bits[-1L] }

        // Fault (B): the write path silently accepts -7..-1 and does nothing.
        shouldThrow<Throwable> { bits[-1L] = true }
        shouldThrow<Throwable> { bits[-3L] = true }
    }

    /*
     * bitstring_fallback_deserializer_leaks_non_serialization_exceptions
     *
     * BUG: Asn1BitStringComponentSerializer.deserialize wraps neither the "<padding>:<base64>"
     * parsing nor the padding-bit validation, so malformed JSON input escapes as raw
     * IllegalArgumentException, NumberFormatException, Base64 decoding failures or
     * Asn1Exception.
     *
     * TRIGGER: "6:IA==" (padding 6 but a non-zero padding bit), "1" (no separator),
     * "99999999999999:AAAA" (padding overflow), "1:!!!" (invalid base64).
     */
    "bitstring_fallback_deserializer_leaks_non_serialization_exceptions" {
        listOf("\"6:IA==\"", "\"1\"", "\"99999999999999:AAAA\"", "\"1:!!!\"", "\"-1:AAAA\"").forEach { payload ->
            shouldThrow<SerializationException> {
                Json.decodeFromString(Asn1BitString.Companion, payload)
            }
        }
    }

}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

@OptIn(ExperimentalStdlibApi::class)
private fun base64(bytes: ByteArray): String = java.util.Base64.getEncoder().encodeToString(bytes)

private fun measureMillis(block: () -> Unit): Long {
    val start = System.nanoTime()
    block()
    return (System.nanoTime() - start) / 1_000_000
}

/**
 * Bytes allocated by [block] on the calling thread (HotSpot's per-thread allocation counter).
 * Unlike a heap-delta probe this is immune to concurrently running tests, and it captures the
 * transient allocations the bounded-rendering findings are about, not just retained size.
 */
private fun allocatedBytes(block: () -> Unit): Long {
    val bean = java.lang.management.ManagementFactory.getThreadMXBean() as com.sun.management.ThreadMXBean
    val id = Thread.currentThread().id
    val before = bean.getThreadAllocatedBytes(id)
    block()
    return bean.getThreadAllocatedBytes(id) - before
}
