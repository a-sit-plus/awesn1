// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.benchmarks

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.encoding.Asn1
import org.openjdk.jmh.annotations.Benchmark
import org.openjdk.jmh.annotations.Scope
import org.openjdk.jmh.annotations.State

/**
 * Cost of constructing a programmatic SET, which sorts its children via `DerEncodedElementComparator`. Children are
 * built FRESH each op (their encoding caches cold), so this exercises what the comparator actually materializes
 * while sorting — the case where ordering by the cheap tag+length key (instead of forcing each member's full DER
 * encoding) pays off. 16 distinct context-tagged members, each a non-trivial SEQUENCE.
 */
@State(Scope.Benchmark)
open class SetSortBenchmark {

    @Benchmark
    fun buildSortedSet(): Asn1Element = Asn1.Set {
        for (i in 0 until 16) +Asn1.ExplicitlyTagged(i.toULong()) { repeat(10) { +Asn1.Int(it.toLong()) } }
    }
}
