// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.benchmarks

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Structure
import at.asitplus.awesn1.crypto.pki.X509Certificate
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.serialization.DER
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.x509.Certificate

/**
 * Retained-heap probe behind the memory table in `docs/docs/lowlevel.md#memory`. Not a JMH benchmark — it measures
 * space, not time — but it lives here because it needs exactly the benchmark module's classpath (core, kxs, crypto
 * and Bouncy Castle) and the same real-world corpus as [ResourceCorpusBenchmark].
 *
 * Run it with `./gradlew :benchmarks:memoryProbe`.
 *
 * Method: the corpus bytes are loaded once and stay live throughout, so they are inside the baseline rather than
 * inside any reported figure. For each representation, used heap is sampled after repeated [System.gc] with only
 * that baseline live, the whole corpus is parsed into a list, used heap is sampled again, and the difference is
 * reported. Each representation is measured [REPEATS] times; the readings should agree closely — a run where they
 * do not is a run where the collector got in the way, and should be discarded rather than published.
 *
 * The figures are indicative (GC/JIT/JVM-version sensitive) and describe **retained** heap. Transient allocation
 * during parsing is a separate, larger number and is not measured here.
 */
private const val REPEATS = 2

/** GC settling: repeated collections, because a single [System.gc] rarely reaches a stable used-heap reading. */
private const val GC_ROUNDS = 6
private const val GC_PAUSE_MS = 120L

private fun usedHeap(): Long {
    val runtime = Runtime.getRuntime()
    repeat(GC_ROUNDS) {
        System.gc()
        Thread.sleep(GC_PAUSE_MS)
    }
    return runtime.totalMemory() - runtime.freeMemory()
}

private fun mib(bytes: Long): String = "%.2f MiB".format(bytes / 1048576.0)

/**
 * The only reference to the graph being measured. Holding it here rather than in a local is deliberate: a local slot
 * keeps its reference until the frame reassigns it, which would leave the previous representation reachable during
 * the *next* baseline sample and silently understate that one.
 */
@Volatile
private var measured: Any? = null

/**
 * Parses [corpus] into representation [label] and reports the heap that representation retains. Blobs that fail to
 * parse are skipped, and only the bytes of those that succeeded count towards the ratio — the three representations
 * accept slightly different subsets, so each gets its own denominator.
 */
private fun <T> measure(label: String, corpus: List<ByteArray>, build: (ByteArray) -> T) {
    // One discarded pass first: the first use of a decoder pulls in its own one-time statics (serializer descriptors,
    // OID name tables, Bouncy Castle's provider internals), which are per-JVM, not per-certificate, and would
    // otherwise land entirely on the first reading — worth ~2 MiB on the typed model.
    warmUp(corpus, build)

    repeat(REPEATS) {
        val baseline = usedHeap()
        var ownBytes = 0L
        var parsed = 0
        measured = corpus.mapNotNull { blob ->
            runCatching { build(blob) }.getOrNull()?.also { ownBytes += blob.size }
        }.also { parsed = it.size }
        val retained = usedHeap() - baseline
        println(
            "%-34s parsed=%4d  own DER=%9s  retained=%9s  vs raw DER=%.2fx".format(
                label, parsed, mib(ownBytes), mib(retained), retained.toDouble() / ownBytes
            )
        )
        measured = null
    }
}

/** Builds every representation once and drops it, so the measured readings see only steady-state allocation. */
private fun <T> warmUp(corpus: List<ByteArray>, build: (ByteArray) -> T) {
    measured = corpus.mapNotNull { runCatching { build(it) }.getOrNull() }
    measured = null
}

/**
 * Total TLV element count across [corpus], iteratively — the corpus is real-world input of unbounded depth. Parsing
 * happens inside this function so that the trees die with its frame and cannot inflate the first heap baseline.
 */
private fun countElements(corpus: List<ByteArray>): Long {
    var elements = 0L
    val pending = ArrayDeque(corpus.mapNotNull { runCatching { Asn1Element.parse(it) }.getOrNull() })
    while (pending.isNotEmpty()) {
        val element = pending.removeLast()
        elements++
        if (element is Asn1Structure) element.children.forEach(pending::addLast)
    }
    return elements
}

fun main() {
    val corpus = Fixtures.loadCorpus()
    require(corpus.isNotEmpty()) { "empty corpus — is ${Fixtures.CORPUS_PROPERTY} pointing at the resources dir?" }
    val corpusBytes = corpus.sumOf { it.size.toLong() }

    val elements = countElements(corpus)
    println("corpus: ${corpus.size} DER blobs, ${mib(corpusBytes)}, $elements TLV elements")
    println("JVM:    ${System.getProperty("java.vm.name")} ${System.getProperty("java.version")}, " +
            "max heap ${mib(Runtime.getRuntime().maxMemory())}")
    println()

    measure("awesn1 raw Asn1Element tree", corpus) { Asn1Element.parse(it) }
    measure("awesn1 typed X509Certificate", corpus) { DER.decodeFromByteArray(X509Certificate.serializer(), it) }
    measure("Bouncy Castle X509 Certificate", corpus) { Certificate.getInstance(ASN1Primitive.fromByteArray(it)) }
}
