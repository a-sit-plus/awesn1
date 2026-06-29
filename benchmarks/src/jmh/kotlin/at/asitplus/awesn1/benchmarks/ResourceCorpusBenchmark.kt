// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.benchmarks

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.io.encodeToDer
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import org.bouncycastle.asn1.ASN1Encoding
import org.bouncycastle.asn1.ASN1Primitive
import org.openjdk.jmh.annotations.Benchmark
import org.openjdk.jmh.annotations.OutputTimeUnit
import org.openjdk.jmh.annotations.Scope
import org.openjdk.jmh.annotations.Setup
import org.openjdk.jmh.annotations.State
import org.openjdk.jmh.infra.Blackhole
import java.util.concurrent.TimeUnit

/**
 * Raw TLV decode/encode over the real-world DER/PEM corpus shipped in `crypto/src/jvmTest/resources` (certificate
 * fixtures, attestation chains, real TLS certs). One `@Benchmark` invocation sweeps the entire corpus once.
 *
 * Parsing is best-effort: each blob is fed to both libraries wrapped in `runCatching`, so malformed inputs simply
 * yield `null` and never abort the sweep — we only care about throughput on a realistic mix of inputs. Both
 * libraries pay the identical try/catch cost, keeping the comparison fair.
 */
@State(Scope.Benchmark)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
open class ResourceCorpusBenchmark {

    private lateinit var corpus: List<ByteArray>
    private lateinit var awesn1Parsed: List<Asn1Element>
    private lateinit var bcParsed: List<ASN1Primitive>

    @Setup
    fun setup() {
        corpus = Fixtures.loadCorpus()
        require(corpus.isNotEmpty()) { "empty corpus — is ${Fixtures.CORPUS_PROPERTY} pointing at the resources dir?" }
        // pre-parse once for the encode benchmarks (only blobs that actually decode are re-encoded)
        awesn1Parsed = corpus.mapNotNull { runCatching { Asn1Element.parse(it) }.getOrNull() }
        bcParsed = corpus.mapNotNull { runCatching { ASN1Primitive.fromByteArray(it) }.getOrNull() }
    }

    @Benchmark
    fun awesn1Decode(bh: Blackhole) {
        for (blob in corpus) bh.consume(runCatching { Asn1Element.parse(blob) }.getOrNull())
    }

    @Benchmark
    fun bouncyCastleDecode(bh: Blackhole) {
        for (blob in corpus) bh.consume(runCatching { ASN1Primitive.fromByteArray(blob) }.getOrNull())
    }

    @Benchmark
    fun awesn1Encode(bh: Blackhole) {
        // fresh buffer per element so the cached `derEncoded` lazy is never primed — real re-encode each time
        for (tree in awesn1Parsed) bh.consume(runCatching {
            val buffer = Buffer(); tree.encodeToDer(buffer); buffer.readByteArray()
        }.getOrNull())
    }

    @Benchmark
    fun bouncyCastleEncode(bh: Blackhole) {
        for (tree in bcParsed) bh.consume(runCatching { tree.getEncoded(ASN1Encoding.DER) }.getOrNull())
    }
}