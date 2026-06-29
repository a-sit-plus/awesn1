// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.benchmarks

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.encoding.parse
import org.openjdk.jmh.annotations.Benchmark
import org.openjdk.jmh.annotations.Param
import org.openjdk.jmh.annotations.Scope
import org.openjdk.jmh.annotations.Setup
import org.openjdk.jmh.annotations.State

/**
 * Cost of the (stack-safe, `DeepRecursiveFunction`-based) content-length post-order walk. `contentLengthLong` is
 * cached per element, so it can only be measured on a COLD tree — hence each invocation parses a fresh tree and
 * then forces the length. The `parseOnly` baseline isolates parse cost; `parseThenLength − parseOnly` is the walk.
 */
@State(Scope.Benchmark)
open class LengthBenchmark {

    @Param("cert", "integers", "mixed")
    lateinit var fixture: String

    private lateinit var der: ByteArray

    @Setup
    fun setup() {
        der = when (fixture) {
            "cert" -> Fixtures.certificateDer()
            "integers" -> Fixtures.integerHeavyDer()
            "mixed" -> Fixtures.mixedSmallDer()
            else -> error("unknown fixture $fixture")
        }
    }

    @Benchmark
    fun parseOnly(): Asn1Element = Asn1Element.parse(der)

    @Benchmark
    fun parseThenLength(): Long = Asn1Element.parse(der).overallLengthLong
}
