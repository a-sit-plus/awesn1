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
import org.openjdk.jmh.annotations.Param
import org.openjdk.jmh.annotations.Scope
import org.openjdk.jmh.annotations.Setup
import org.openjdk.jmh.annotations.State
import java.util.concurrent.TimeUnit

/**
 * Apples-to-apples comparison of the raw ASN.1 TLV layer: awesn1's [Asn1Element] vs Bouncy Castle's
 * [ASN1Primitive], for decoding DER bytes into a tree and re-encoding a tree back to DER.
 *
 * One `@Benchmark` invocation == decoding (or encoding) one whole fixture; JMH controls the iteration count and
 * timing. Results are returned so the JIT cannot eliminate the work as dead code.
 */
@State(Scope.Benchmark)
open class RawTlvBenchmark {

    @Param("cert", "integers", "mixed")
    lateinit var fixture: String

    private lateinit var der: ByteArray

    // pre-parsed trees for the encode benchmarks
    private lateinit var awesn1Tree: Asn1Element
    private lateinit var bcTree: ASN1Primitive

    @Setup
    fun setup() {
        der = when (fixture) {
            "cert" -> Fixtures.certificateDer()
            "integers" -> Fixtures.integerHeavyDer()
            "mixed" -> Fixtures.mixedSmallDer()
            else -> error("unknown fixture $fixture")
        }
        // NB: never touch awesn1Tree.derEncoded / equals / hashCode — that would prime the element's cached
        // encoding and make awesn1Encode measure a field read instead of the actual encode.
        awesn1Tree = Asn1Element.parse(der)
        bcTree = ASN1Primitive.fromByteArray(der)
    }

    @Benchmark
    fun awesn1Decode(): Asn1Element = Asn1Element.parse(der)

    @Benchmark
    fun bouncyCastleDecode(): ASN1Primitive = ASN1Primitive.fromByteArray(der)

    @Benchmark
    fun awesn1Encode(): ByteArray {
        // stream-encode into a fresh buffer: this recomputes the DER every time (the cached `derEncoded` lazy is
        // never initialized), matching BC's getEncoded which also re-serializes on each call
        val buffer = Buffer()
        awesn1Tree.encodeToDer(buffer)
        return buffer.readByteArray()
    }

    @Benchmark
    fun bouncyCastleEncode(): ByteArray = bcTree.getEncoded(ASN1Encoding.DER)

    // repeated `.derEncoded` access on the parsed (structure) tree: this is the path that changed from
    // cached-O(1) to recompute-O(size) when structures stopped retaining their encoding. Quantifies the
    // accepted re-encode cost (e.g. for elements used as hash-map keys / compared repeatedly).
    @Benchmark
    fun awesn1DerEncodedAccess(): ByteArray = awesn1Tree.derEncoded

    // cold encode: a fresh tree each op (length/encoding caches uninitialized) — the build-once-encode-once path.
    // Compare against awesn1Decode (parse only) to isolate the cold encode cost from the parse cost.
    @Benchmark
    fun awesn1EncodeCold(): ByteArray {
        val tree = Asn1Element.parse(der)
        val buffer = Buffer()
        tree.encodeToDer(buffer)
        return buffer.readByteArray()
    }
}