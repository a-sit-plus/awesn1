// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.benchmarks

import at.asitplus.awesn1.ObjectIdentifier
import java.lang.management.ManagementFactory

/**
 * Allocation cost and retained size for decoding a dotted OID string.
 *
 * The amplification figures in `docs/docs/hardening.md#fallback-decoding-limits` come from
 * `ThreadMXBean.getThreadAllocatedBytes`, which is a **cumulative** counter: it says how many bytes passed through
 * the allocator, not how many were live at once. Those are very different numbers when the garbage dies young, and
 * only the second one tells you how much heap a decode actually needs.
 *
 * Two things are reported, and neither is a peak:
 *
 * - **cumulative allocation**, exact, but allocator throughput rather than footprint: it counts bytes that were
 *   collected long before the decode finished, so it overstates what the decode needs to have live (~5x, for the
 *   implementation this was written to characterise).
 * - **retained bytes per instance**, from used heap after repeated collection, which is what an `ObjectIdentifier`
 *   still holds once built.
 *
 * For footprint, run this at decreasing `-Xmx` and note where it starts to fail: that brackets what the decode
 * genuinely needs, and it is the only measurement here that answers the question. A per-pool `peakUsage` sum was
 * reported at one point and removed as misleading — Eden, survivor and old-gen peak at different moments, so adding
 * their maxima exceeds the real high-water mark and can exceed `-Xmx` itself.
 *
 * Input construction is reported separately, because holding a multi-MiB string costs enough to be the binding
 * constraint at very small heaps — a failure there says nothing about the decode.
 *
 * `-Dawesn1.probe.oidChars=<n>` sets the input size (default 5 MiB of characters).
 *
 * For an external profiler (VisualVM, JFR, async-profiler), `-Dawesn1.probe.delaySeconds=<n>` counts down before the
 * decode so there is time to attach, and `-Dawesn1.probe.holdSeconds=<n>` keeps the process alive afterwards with the
 * result still referenced, so a heap dump taken then shows what the decode actually retains. The countdown prints
 * this JVM's PID, since Gradle forks it and it will not be the process you launched.
 */
private fun allocatedBytes(): Long {
    val bean = ManagementFactory.getThreadMXBean() as com.sun.management.ThreadMXBean
    return bean.getThreadAllocatedBytes(Thread.currentThread().id)
}

private fun mib(bytes: Long) = "%.1f MiB".format(bytes / 1048576.0)

/** used heap after repeated collection, i.e. what is actually still held */
private fun settledHeap(): Long {
    val runtime = Runtime.getRuntime()
    repeat(6) { System.gc(); Thread.sleep(100) }
    return runtime.totalMemory() - runtime.freeMemory()
}

@Volatile
private var held: Any? = null

/** Retained bytes per instance for [count] objects built by [build]. */
private fun retainedPer(label: String, count: Int, build: (Int) -> Any) {
    repeat(2) { held = List(count, build); held = null } // warm up: class init and JIT off the books
    val base = settledHeap()
    held = List(count, build)
    val retained = settledHeap() - base
    println("  %-34s %8.1f B each".format(label, retained.toDouble() / count))
    held = null
}

fun main() {
    val chars = System.getProperty("awesn1.probe.oidChars")?.toInt() ?: (5 * 1024 * 1024)
    val maxHeap = Runtime.getRuntime().maxMemory()

    // exact-capacity builder, so making the input does not itself churn. Still needs ~2x the input transiently
    // (the builder's array plus the String's copy), which is the floor of this harness rather than of the decode.
    val dotted = try {
        StringBuilder(chars).apply {
            append("1.2")
            while (length < chars) append(".1")
        }.toString()
    } catch (e: OutOfMemoryError) {
        println("input:      FAILED to build ${mib(chars.toLong())} of characters at max heap ${mib(maxHeap)}")
        println("            (the harness needs ~2x the input to build it; raise -Xmx or lower -PoidProbeChars)")
        return
    }
    println("input:      ${mib(dotted.length.toLong())} of characters, max heap ${mib(maxHeap)}")

    println("pid:        ${ProcessHandle.current().pid()}")
    val delaySeconds = System.getProperty("awesn1.probe.delaySeconds")?.toInt() ?: 0
    if (delaySeconds > 0) {
        println("            attach a profiler now")
        for (remaining in delaySeconds downTo 1) {
            println("            decoding in $remaining s…")
            Thread.sleep(1000)
        }
    }

    repeat(3) { System.gc(); Thread.sleep(100) }
    val allocatedBefore = allocatedBytes()
    val liveBefore = ManagementFactory.getMemoryMXBean().heapMemoryUsage.used

    println("decode:      starting")
    val outcome = try {
        val oid = ObjectIdentifier(dotted)
        "ok, ${mib(oid.bytes.size.toLong())} of content bytes"
    } catch (e: OutOfMemoryError) {
        "OutOfMemoryError: ${e.message}"
    }

    val allocated = allocatedBytes() - allocatedBefore

    val holdSeconds = System.getProperty("awesn1.probe.holdSeconds")?.toInt() ?: 0
    if (holdSeconds > 0) {
        println("holding the decoded value for $holdSeconds s — take a heap dump now")
        held = outcome // keep the decode's result reachable while the profiler looks at it
        Thread.sleep(holdSeconds * 1000L)
    }
    println("outcome:    $outcome")
    println("cumulative: ${mib(allocated)}  (${"%.1f".format(allocated.toDouble() / dotted.length)}x the input) — allocator throughput, NOT footprint")
    println("            for footprint, re-run at decreasing -Xmx and note where it fails")
    println("live before decode: ${mib(liveBefore)}")

    // ---- resident cost: what an ObjectIdentifier still holds once built ----
    // Uses only API present in every version of this class, so the same probe runs against an older baseline.
    println()
    println("retained per ObjectIdentifier:")
    val common = "1.2.840.113549.1.1.11"
    retainedPer("built from string, untouched", 20_000) { ObjectIdentifier(common) }
    retainedPer("built from string, after toString()", 20_000) { ObjectIdentifier(common).also { it.toString() } }
    retainedPer("built from content bytes", 20_000) {
        ObjectIdentifier.decodeFromAsn1ContentBytes(ObjectIdentifier(common).bytes)
    }
    val dense = StringBuilder().apply { append("1.2"); repeat(2000) { append(".1") } }.toString()
    retainedPer("dense, 2002 nodes", 20) { ObjectIdentifier(dense) }
}
