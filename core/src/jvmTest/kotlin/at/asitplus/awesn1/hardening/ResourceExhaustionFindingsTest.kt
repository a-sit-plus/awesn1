// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

/*
 * Resource-exhaustion findings: work or memory unbounded by any caller-visible limit.
 *
 * Two shapes appear here. Diagnostics that render attacker-sized content into an exception message or a bounded
 * `prettyPrint`, and decode paths whose heap cost is a large multiple of the input the caller was allowed to cap.
 * All of them are reproduced at reduced scale (megabytes, not gigabytes) so the suite stays runnable; the asserted
 * bound is still far outside anything a fixed implementation would reach.
 *
 * Each case asserts the CORRECT (post-fix) behaviour, so it FAILS while the defect is present. Where the original
 * reproducer had an A/B shape ("this spelling works, that spelling breaks"), the working leg is kept as an in-test
 * control marked `Control (A)`, so a failure cannot be blamed on a broken fixture. Test names are the finding ids
 * under `findings/<harness>/submitted_humanreadable`.
 */

@file:OptIn(at.asitplus.awesn1.InternalAwesn1Api::class)

package at.asitplus.awesn1

import at.asitplus.awesn1.encoding.decodeAsn1VarBigInt
import at.asitplus.awesn1.encoding.internal.decodeAsn1VarBigInt
import at.asitplus.awesn1.encoding.toAsn1VarInt
import at.asitplus.awesn1.encoding.parseAll
import at.asitplus.awesn1.encoding.readNull
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json

/**
 * Allocation ceiling for parsing the densest legal DER, as a multiple of the wire size. See
 * `der_tree_memory_amplification_vs_limit` below and `lowlevel.md#memory` for what the number means and why it is a
 * ratchet rather than a target.
 */
private const val MAX_DENSE_PARSE_AMPLIFICATION = 72

/**
 * Warm-up passes before an allocation measurement. Class init and the first JIT compilation of a code path cost
 * far more than any bound asserted here, and they are paid by whichever case touches the path first — which makes
 * an un-warmed case pass or fail depending on what else ran in the same JVM.
 */
private const val WARMUP_ITERATIONS = 50

@OptIn(ExperimentalStdlibApi::class)
val ResourceExhaustionFindings by matrixSuite {
    "unbounded diagnostics" - {
        /*
         * customstructure_prettyprinthex_unbounded_transient
         *
         * BUG: Asn1CustomStructure.prettyPrintHeader hex-dumps `content` unbounded — and for a
         * primitive-tagged custom structure `content` RE-ENCODES the whole subtree — while
         * Asn1Element.renderTo evaluates that argument BEFORE its budget check. The documented
         * render limit is therefore defeated by an O(subtree) transient (OOM at attacker scale).
         *
         * TRIGGER: an 8 MiB OCTET STRING inside a primitive-tagged custom structure rendered with
         * toString(limit = 200). Control: the same call on a small payload renders ~177 chars.
         */
        "customstructure_prettyprinthex_unbounded_transient" {
            // The rendered OUTPUT is correctly truncated in both cases - the defect is the
            // transient allocation made while building the (discarded) header, so that is what is
            // measured here.

            val small = Asn1CustomStructure.asPrimitive(
                listOf(Asn1Primitive(Asn1Element.Tag.OCTET_STRING, ByteArray(8) { 0x41 })),
                16u,
                TagClass.CONTEXT_SPECIFIC,
            )
            // Warm up first: the first render in the JVM pays class init and JIT for the whole render machinery,
            // which costs more than the bound this case asserts and has nothing to do with the payload.
            repeat(WARMUP_ITERATIONS) { consume(small.toString(limit = 200)) }

            // Control (A): a small payload costs almost nothing.
            (allocatedBytes { consume(small.toString(limit = 200)) } < 1024 * 1024) shouldBe true

            // Fault (B): an 8 MiB subtree used to be fully re-encoded and hex-dumped for a 200-char render.
            val big = Asn1CustomStructure.asPrimitive(
                listOf(Asn1Primitive(Asn1Element.Tag.OCTET_STRING, ByteArray(8 * 1024 * 1024) { 0x41 })),
                16u,
                TagClass.CONTEXT_SPECIFIC,
            )
            (allocatedBytes { consume(big.toString(limit = 200)) } < 1024 * 1024) shouldBe true
        }

        /*
         * prettyprint_encaps_octetstring_unbounded_hex_transient
         *
         * BUG: Asn1EncapsulatingOctetString.prettyPrintHeader hex-dumps its content without
         * consulting the renderer's remaining budget, so the documented-bounded prettyPrint
         * materialises an O(content) String and dies with OutOfMemoryError at attacker scale.
         * The byte-identical RAW OCTET STRING renders correctly on the same heap (control).
         *
         * TRIGGER: an 8 MiB encapsulating OCTET STRING rendered with limit = 100.
         */
        "prettyprint_encaps_octetstring_unbounded_hex_transient" {
            val filler = Asn1Primitive(Asn1Element.Tag.OCTET_STRING, ByteArray(8 * 1024 * 1024) { 0x41 })
            val raw = Asn1Primitive(Asn1Element.Tag.OCTET_STRING, ByteArray(8 * 1024 * 1024) { 0x41 })
            val encapsulating = Asn1EncapsulatingOctetString(listOf(filler))

            // Warm up both shapes, for the same reason as the case above: the raw variant renders through the
            // primitive branch and the encapsulating one through the structure branch, so warming one does not
            // compile the other.
            val smallEncapsulating = Asn1EncapsulatingOctetString(
                listOf(Asn1Primitive(Asn1Element.Tag.OCTET_STRING, ByteArray(8) { 0x41 }))
            )
            repeat(WARMUP_ITERATIONS) {
                consume(raw.prettyPrint(limit = 100))
                consume(smallEncapsulating.prettyPrint(limit = 100))
            }

            // Control (A): the byte-identical RAW OCTET STRING renders within budget.
            (allocatedBytes { consume(raw.prettyPrint(limit = 100)) } < 1024 * 1024) shouldBe true

            // Fault (B): the encapsulating variant used to hex-dump its whole content regardless.
            (allocatedBytes { consume(encapsulating.prettyPrint(limit = 100)) } < 1024 * 1024) shouldBe true
        }

        /*
         * readnull_error_message_unbounded_hex
         *
         * BUG: Asn1Primitive.readNull() embeds the FULL hex of the offending content in its
         * Asn1Exception message, so rejecting an attacker NULL of size L allocates a ~4L-byte
         * String on the rejection path — an OOM inside the very code meant to fail gracefully.
         *
         * TRIGGER: a NULL primitive with 4 MiB of content; the diagnostic must stay bounded.
         */
        "readnull_error_message_unbounded_hex" {
            val bogusNull = Asn1Primitive(Asn1Element.Tag.NULL, ByteArray(4 * 1024 * 1024) { 0x41 })
            val message = shouldThrow<Asn1Exception> { bogusNull.readNull() }.message ?: ""
            (message.length < 4096) shouldBe true
        }

        /*
         * real_minimality_error_message_unbounded_hex
         *
         * BUG: the strict-minimality rejection path in Asn1Real.decodeFromAsn1ContentBytes
         * embeds the FULL hex of both the input and the re-encoding in its message, so every
         * rejected REAL costs ~2-4x the attacker-chosen content size in transient heap.
         *
         * TRIGGER: a 1 MiB non-minimally normalised REAL; the diagnostic must stay bounded.
         */
        "real_minimality_error_message_unbounded_hex" {
            val content = ByteArray(1024 * 1024).also {
                it[0] = 0x80.toByte(); it[1] = 0x00; it[2] = 0x01
            }
            val message = shouldThrow<Asn1Exception> {
                Asn1Real.decodeFromAsn1ContentBytes(content, lenient = false)
            }.message ?: ""
            (message.length < 4096) shouldBe true
        }
    }

    "memory amplification and missing limits" - {
        /*
         * der_tree_memory_amplification_vs_limit
         *
         * NOT A DEFECT — a bounded characteristic, and this case guards the bound.
         *
         * The finding argued that `doParse` checks only BYTE lengths and allocates one Asn1Element
         * per TLV with no per-node accounting, so a host setting the documented byte limit still
         * OOMs. The first half is true; the conclusion does not follow. Deferred semantic parsing
         * means keeping a structure to interpret later, so a tree that costs more than its wire
         * bytes is the product, not an accident — and the smallest legal TLV is two bytes, so a
         * byte limit of L admits at most L/2 elements. The byte limit IS a heap bound. What was
         * missing was the constant, which is now documented in lowlevel.md#memory.
         *
         * Per-element accounting would add nothing that L/2 does not already give.
         *
         * So this asserts the documented factor rather than an unachievable one. The floor is
         * header + tag reference + content reference, i.e. roughly 12-16x on maximally dense input
         * even if everything else were free.
         *
         * TRIGGER: the 2-byte TLV 05 00 (NULL) repeated 200_000 times — the densest input that
         * exists — parsed with the limit set exactly to the payload size.
         */
        "der_tree_memory_amplification_vs_limit" {
            val count = 200_000
            val input = ByteArray(count * 2).also { for (i in 0 until count) it[i * 2] = 0x05 }

            // Warm up first. Cold, the JIT has not yet scalar-replaced the parser's transient tuples, which roughly
            // doubles the measured allocation (~110x vs ~54x) and would drown the signal this bound is meant to carry.
            // Warming up on a small input rather than on `input` keeps this cheap while compiling the same paths, and
            // makes the case self-sufficient rather than dependent on which other suites happened to run first.
            val warmup = ByteArray(64).also { for (i in 0 until 32) it[i * 2] = 0x05 }
            repeat(WARMUP_ITERATIONS) { consume(Asn1Element.parseAll(warmup, limit = warmup.size.toLong())) }
            repeat(3) { consume(Asn1Element.parseAll(input, limit = input.size.toLong())) }

            var parsed: List<Asn1Element> = emptyList()
            val allocated = allocatedBytes { parsed = Asn1Element.parseAll(input, limit = input.size.toLong()) }
            parsed.size shouldBe count

            // Measured ~54x. The bound sits between that and the ~99x this cost before tag interning and shared
            // empty content, so it stays quiet through normal variation but fails if that work is undone.
            (allocated < input.size.toLong() * MAX_DENSE_PARSE_AMPLIFICATION) shouldBe true
        }

        /*
         * fallback_b64_serializer_api_no_limit_knob
         *
         * BUG (fixed): Asn1ElementFallbackBase64SerializerBase.deserialize neither accepted nor
         * propagated a limit, so a host had no API surface at all with which to bound a base64 DER
         * field under a non-DER format. The amplification itself is the documented characteristic
         * of deferred semantic parsing (see der_tree_memory_amplification_vs_limit above); what
         * was missing was the knob, and the fallback path had none while `DER { maxInputLength }`
         * and the streaming `limit` bounded every other route into the parser.
         *
         * The serializers now implement BoundedFallbackSerializer: `bounded(limit)` for call sites
         * that name their serializer, and the global default for the `@Serializable(with = ...)`
         * path, which is the only knob that reaches element-typed properties declared by awesn1
         * itself. The check runs on the encoded string, before the Base64 decode allocates.
         *
         * TRIGGER: a context-tagged primitive whose content is 100_000 copies of the 2-byte TLV
         * 80 00, delivered as a JSON base64 string, decoded through both knobs.
         */
        "fallback_b64_serializer_api_no_limit_knob" {
            val children = 100_000
            val content = ByteArray(children * 2).also { for (i in 0 until children) it[i * 2] = 0x80.toByte() }
            val der = byteArrayOf(0x85.toByte(), 0x83.toByte()) +
                    byteArrayOf(
                        (content.size ushr 16).toByte(),
                        (content.size ushr 8).toByte(),
                        content.size.toByte(),
                    ) + content
            val json = "\"" + base64(der) + "\""

            // Control (A): within its limit the payload still decodes, deferred children and all. Measured
            // twice, because the first pass pays class init and JIT warm-up, which would otherwise land on
            // whichever leg runs first rather than on the tree.
            var accepted = 0L
            repeat(2) {
                accepted = allocatedBytes {
                    Json.decodeFromString(Asn1CustomStructureFallbackBase64Serializer, json)
                        .children.size shouldBe children
                }
            }

            // Fault (B1): an explicitly bounded instance refuses it, and refuses it before the Base64
            // decode. Both legs pay the same JSON parse, so the difference between them is the tree that
            // the rejected leg never builds.
            val bounded = Asn1CustomStructureFallbackBase64Serializer.bounded(1024)
            val rejected = allocatedBytes {
                shouldThrow<SerializationException> { Json.decodeFromString(bounded, json) }
            }
            // measured ~20.4 MiB accepted vs ~273 KiB rejected, i.e. 74x; asserted at one order of magnitude
            (rejected * 10 < accepted) shouldBe true

            // Fault (B2): the global default reaches the singleton, i.e. the `@Serializable(with = ...)`
            // path a host cannot otherwise get at. Read per decode, so ordering against class init
            // does not matter.
            val previous = BoundedFallbackSerializer.defaultDecodingLimit
            try {
                BoundedFallbackSerializer.defaultDecodingLimit = 1024
                shouldThrow<SerializationException> {
                    Json.decodeFromString(Asn1CustomStructureFallbackBase64Serializer, json)
                }
            } finally {
                BoundedFallbackSerializer.defaultDecodingLimit = previous
            }

            // ...and restoring it restores the control.
            Json.decodeFromString(Asn1CustomStructureFallbackBase64Serializer, json)
                .children.size shouldBe children
        }

        /*
         * varbig_source_decoder_unbounded_no_limit
         *
         * BUG (fixed): decodeAsn1VarBigUIntValue(Source) capped neither the number of continuation
         * bytes it accumulated nor exposed the `limit: Long` every sibling streaming API requires,
         * and it silently ACCEPTED an unterminated varint at stream exhaustion instead of failing.
         * Attacker-streamed continuation bytes drove ~3x allocation into a raw OutOfMemoryError,
         * which no `catch (Asn1Exception)` in the host app can contain.
         *
         * The decode now runs through a BoundedSource, so the bound is enforced BEFORE each read
         * rather than after the heap is gone, and exhaustion without a terminator is an error.
         *
         * TRIGGER: 1024 unterminated 0xFF bytes — the capped siblings raise "Unterminated ASN.1
         * unsigned varint" and this path used to return a value — plus a 1 MiB stream of them
         * against a 64-byte limit.
         */
        "varbig_source_decoder_unbounded_no_limit" {
            // Control (A): a well-formed varint still decodes, from both a ByteArray and a source.
            val wellFormed = Asn1Integer.fromDecimalString("123456789012345678901234567890").toAsn1VarInt()
            wellFormed.decodeAsn1VarBigInt().first.toDecimalString() shouldBe "123456789012345678901234567890"
            wellFormed.wrapInUnsafeSource().decodeAsn1VarBigInt(wellFormed.size.toLong())
                .first.toDecimalString() shouldBe "123456789012345678901234567890"

            // Fault (B1): an unterminated varint is malformed input, not a partial value.
            shouldThrow<IllegalArgumentException> { ByteArray(1024) { 0xFF.toByte() }.decodeAsn1VarBigInt() }

            // Fault (B2): the streaming entry point takes a limit, and enforces it BEFORE reading rather
            // than after the heap is gone — exactly `limit` bytes are consumed, and the rest of the
            // attacker's stream is never touched, so the accumulator can never outgrow the bound.
            val stream = ByteArray(4096) { 0xFF.toByte() }.wrapInUnsafeSource()
            shouldThrow<IllegalArgumentException> { stream.decodeAsn1VarBigInt(64) }
            var untouched = 0
            while (!stream.exhausted()) {
                stream.readByte()
                untouched++
            }
            untouched shouldBe 4096 - 64
        }
    }
}
