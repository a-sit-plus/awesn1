// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

/*
 * Lifecycle and DSL findings: defects in how the format is built rather than in what it encodes.
 *
 * The default `DER` singleton's startup-only, unsynchronised lifecycle is documented as an explicit limitation.
 * The remaining findings exercise public API behaviour that the library controls directly.
 *
 * Each case asserts the CORRECT (post-fix) behaviour, so it FAILS while the defect is present. Where the original
 * reproducer had an A/B shape ("this spelling works, that spelling breaks"), the working leg is kept as an in-test
 * control marked `Control (A)`, so a failure cannot be blamed on a broken fixture. Test names are the finding ids
 * under `findings/<harness>/submitted_humanreadable`.
 */

package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.append
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.builtins.serializer

@OptIn(ExperimentalSerializationApi::class, ExperimentalStdlibApi::class)
val SerializationLifecycleFindings by matrixSuite {
    "builder DSL" - {
        /*
         * dsl_unaryplus_numeric_operand_drop
         *
         * BUG: DslAddons declared a generic extension `Serializable.unaryPlus()`, but Byte /
         * Short / Int / Long / Float / Double all have a MEMBER `unaryPlus()` in the stdlib, and
         * members always outrank extensions. The documented `+value` form therefore resolves to
         * plain numeric negation-identity and the operand is discarded. The project's unused-return-value checker
         * warns about that expression, but downstream projects are not required to enable it.
         *
         * FIX: the generic operator was removed. The named `append(...)` API has no operator-resolution ambiguity.
        */
        "dsl_unaryplus_numeric_operand_drop" {
            with(DER) {
                Asn1.Sequence {
                    append(Int.serializer(), 5)
                    append(Long.serializer(), 6L)
                }
            }.children.size shouldBe 2
            with(DER) {
                Asn1.Set {
                    append(2)
                    append(1)
                }
            }.children.size shouldBe 2
        }
    }

}
