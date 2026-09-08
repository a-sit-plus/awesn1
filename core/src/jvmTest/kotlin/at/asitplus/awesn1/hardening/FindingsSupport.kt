// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(ExperimentalStdlibApi::class)

/*
 * Shared fixtures for the core findings suites (`*FindingsTest.kt` in this package).
 *
 * The models are the @Serializable shapes the findings need; the helpers are the measurement and probe
 * utilities they share. They live here rather than in one suite so that a finding can be filed under the
 * domain it belongs to without dragging its fixtures along.
 */

package at.asitplus.awesn1

import at.asitplus.awesn1.encoding.decodeToAsn1Integer

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

@OptIn(ExperimentalStdlibApi::class)
internal fun base64(bytes: ByteArray): String = java.util.Base64.getEncoder().encodeToString(bytes)

internal fun measureMillis(block: () -> Unit): Long {
    val start = System.nanoTime()
    block()
    return (System.nanoTime() - start) / 1_000_000
}

/**
 * Bytes allocated by [block] on the calling thread (HotSpot's per-thread allocation counter).
 * Unlike a heap-delta probe this is immune to concurrently running tests, and it captures the
 * transient allocations the bounded-rendering findings are about, not just retained size.
 */
internal fun allocatedBytes(block: () -> Unit): Long {
    val bean = java.lang.management.ManagementFactory.getThreadMXBean() as com.sun.management.ThreadMXBean
    val id = Thread.currentThread().id
    val before = bean.getThreadAllocatedBytes(id)
    block()
    return bean.getThreadAllocatedBytes(id) - before
}

internal fun decimalOf(magnitudeBytes: Int): String =
    java.math.BigInteger(1, ByteArray(magnitudeBytes).also { it[0] = 1 }).toString()

/** Declares A = Asn1Primitive so that any CONSTRUCTED payload fails the unchecked cast. */
internal object TensorixIntPemDecoder : Asn1PemDecodable<Asn1Primitive, Asn1Integer> {
    override val canonicalPemLabel: String = "TENSORIX INTEGER"
    override fun doDecode(src: Asn1Primitive): Asn1Integer = src.decodeToAsn1Integer()
}
