// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

/*
 * Resource-limit findings: configured bounds that do not bind.
 *
 * `maxNestingDepth` and `maxInputLength` are the format's two advertised defences against hostile input. The depth
 * guard is a logical counter that ignores real stack consumption, so a StackOverflowError - a VirtualMachineError,
 * which `nonFatalOrThrow` deliberately rethrows - escapes instead of the documented catchable SerializationException.
 * The input cap defaults to a value no ByteArray can exceed, so it never rejects anything.
 *
 * Each case asserts the CORRECT (post-fix) behaviour, so it FAILS while the defect is present. Where the original
 * reproducer had an A/B shape ("this spelling works, that spelling breaks"), the working leg is kept as an in-test
 * control marked `Control (A)`, so a failure cannot be blamed on a broken fixture. Test names are the finding ids
 * under `findings/<harness>/submitted_humanreadable`.
 */

package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.encoding.parse
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerializationException
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.serializer

@OptIn(ExperimentalSerializationApi::class, ExperimentalStdlibApi::class)
val SerializationResourceLimitFindings by matrixSuite {
    "recursion depth guards" - {
        "built-in ASN.1 element trees respect maxNestingDepth" {
            val der = DER { maxNestingDepth = 8 }
            val deep = nestedSequenceDer(9)
            val element = Asn1Element.parse(deep)

            shouldThrow<SerializationException> { der.encodeToByteArray(Asn1Element.serializer(), element) }
            shouldThrow<SerializationException> { der.decodeFromByteArray(Asn1Element.serializer(), deep) }
        }

        /*
         * depthguard_soe_bypass
         *
         * BUG: DerDepthGuard was a pure logical counter (default 128) that ignored how many real
         * JVM frames each level burns, and internal-utils' `nonFatalOrThrow` rethrows any
         * VirtualMachineError instead of wrapping it. On a small-stack thread the stack dies
         * before the counter reaches maxNestingDepth, so an uncaught StackOverflowError escapes
         * `DER.decodeFromByteArray` although the KDoc promises a catchable SerializationException.
         *
         * TRIGGER: decode 127 nested SEQUENCEs on a 64 KiB-stack
         * thread. Anything that comes out must be a SerializationException, never an Error.
         */
        "depthguard_soe_bypass" {
            val thrown = onThreadWithStack(64 * 1024L) {
                DER.decodeFromDer<DsPlainRecursive>(nestedSequenceDer(127))
            }
            // Correct behaviour: either a clean decode or a catchable SerializationException.
            // Today: java.lang.StackOverflowError (a VirtualMachineError) escapes.
            if (thrown != null) thrown.shouldBeInstanceOf<SerializationException>()
        }

        /*
         * enc_depthguard_soe_smallstack
         *
         * BUG: the encode-side twin of depthguard_soe_bypass. DerEncoder.beginStructure bounded
         * recursion only by a logical counter whose former default exceeded constrained-stack headroom.
         *
         * TRIGGER: build a depth-127 recursive graph in memory and encode it on a 64 KiB-stack
         * thread. Anything thrown must be a catchable SerializationException, not an Error.
         */
        "enc_depthguard_soe_smallstack" {
            val graph = buildRecursiveGraph(127)
            val thrown = onThreadWithStack(64 * 1024L) { DER.encodeToByteArray(graph) }
            if (thrown != null) thrown.shouldBeInstanceOf<SerializationException>()
        }

        /*
         * max_nesting_depth_guard_silent_disable
         *
         * BUG: DerBuilder.build() never validated maxNestingDepth against conservative platform
         * recursion headroom. A huge value silently disabled DerDepthGuard.
         *
         * TRIGGER: reject a value that would silently disable the guard.
         */
        "max_nesting_depth_guard_silent_disable" {
            DER { maxNestingDepth = 65_536 }.configuration.maxNestingDepth shouldBe 65_536
            shouldThrow<IllegalArgumentException> { DER { maxNestingDepth = Int.MAX_VALUE } }
        }
    }

    "input size limits" - {
        /*
         * der_maxinput_unbounded
         *
         * BUG: DerConfiguration.maxInputLength defaults to Int.MAX_VALUE, and the only
         * enforcement is `require(source.size <= limit)` in Asn1Element.parse. A JVM ByteArray
         * can never exceed Int.MAX_VALUE bytes, so the advertised cap is a guaranteed no-op for
         * every possible ByteArray input while the decode path holds ~2x the input in heap.
         *
         * TRIGGER: feed the same 1 MiB SEQUENCE{OCTET STRING} to the default instance and to
         * DER { maxInputLength = 1024 }. The configured cap rejects (control, A); the default
         * accepts (B). The assertion is on the default itself: a limit that cannot ever engage
         * is not a limit.
         */
        "der_maxinput_unbounded" {
            val payload = DER.encodeToByteArray(DsWrappedOctet(ByteArray(1024 * 1024)))

            // Control (A): a configured cap does reject — the mechanism works.
            shouldThrow<SerializationException> {
                DER { maxInputLength = 1024L }.decodeFromDer<DsWrappedOctet>(payload)
            }

            // Fault (B): the default cap is unreachable for any ByteArray, so it never rejects.
            DER.decodeFromDer<DsWrappedOctet>(payload).payload.size shouldBe 1024 * 1024
            (DER.configuration.maxInputLength < Int.MAX_VALUE.toLong()) shouldBe true
        }
    }
}
