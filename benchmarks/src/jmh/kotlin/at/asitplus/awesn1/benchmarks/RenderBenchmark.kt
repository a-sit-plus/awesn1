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
 * Throughput of the (stack-safe, `DeepRecursiveFunction`-based) string renderer — compact `toString` and indented
 * `prettyPrint` — over the three fixtures. Rendering is uncached, so each invocation runs the full walk.
 */
@State(Scope.Benchmark)
open class RenderBenchmark {

    @Param("cert", "integers", "mixed")
    lateinit var fixture: String

    private lateinit var tree: Asn1Element

    @Setup
    fun setup() {
        tree = Asn1Element.parse(
            when (fixture) {
                "cert" -> Fixtures.certificateDer()
                "integers" -> Fixtures.integerHeavyDer()
                "mixed" -> Fixtures.mixedSmallDer()
                else -> error("unknown fixture $fixture")
            }
        )
    }

    @Benchmark
    fun prettyPrint(): String = tree.prettyPrint()

    @Benchmark
    fun compactToString(): String = tree.toString()
}
