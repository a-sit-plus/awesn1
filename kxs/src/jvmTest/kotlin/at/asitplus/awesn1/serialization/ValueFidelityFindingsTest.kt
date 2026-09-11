// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

/*
 * Value-fidelity findings: decode succeeds, but the value does not represent the wire.
 *
 * Before the fixes, duplicates were folded away, nulls vanished from collections, negative integers arrived as large
 * unsigned ones and distinct strings normalised to the same text. Correct handling either preserves the value exactly
 * or rejects an unrepresentable/unsupported input with SerializationException.
 *
 * Each case asserts the CORRECT (post-fix) behaviour, so it FAILS while the defect is present. Where the original
 * reproducer had an A/B shape ("this spelling works, that spelling breaks"), the working leg is kept as an in-test
 * control marked `Control (A)`, so a failure cannot be blamed on a broken fixture. Test names are the finding ids
 * under `findings/<harness>/submitted_humanreadable`.
 */

package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.Asn1CustomStructure
import at.asitplus.awesn1.Asn1Element
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlin.jvm.JvmInline
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.SetSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.serializer

@OptIn(ExperimentalSerializationApi::class, ExperimentalStdlibApi::class)
val SerializationValueFidelityFindings by matrixSuite {
    "SET OF and MAP multiplicity" - {
        /*
         * lenientset_equals_multiplicity_collapse
         *
         * BUG: LenientSet.equals/hashCode collapse through `elements.toSet()`, i.e. they are
         * multiplicity-INsensitive, while size, iteration and serialize() are multiplicity-
         * SENSITIVE. A wire-decoded set carrying duplicates therefore compares equal to (and
         * hashes like) a clean deduplicated set, yet re-encodes to different DER. Consumers that
         * dedup/cache verified models by equals/hashCode fold the attacker object onto the clean
         * one.
         *
         * TRIGGER: decode SET [2,1,2], compare against the clean set {1,2}. They differ in size
         * and in re-encoded bytes, so they must not be equal, must not share a hash bucket
         * identity, and must not collapse inside a HashSet.
         */
        "lenientset_equals_multiplicity_collapse" {
            val wire = Asn1CustomStructure(
                listOf(DER.encodeToTlv(2), DER.encodeToTlv(1), DER.encodeToTlv(2)),
                Asn1Element.Tag.SET.tagValue,
            )
            val decoded = DER.decodeFromTlv<LenientSet<Int>>(wire)
            val clean = LenientSet(linkedSetOf(1, 2))

            // Control (A): the two objects genuinely differ — different size, different DER.
            decoded.size shouldBe 3
            clean.size shouldBe 2
            DER.encodeToTlv(LenientSet.Serializer(Int.serializer()), decoded).derEncoded shouldNotBe
                    DER.encodeToTlv(LenientSet.Serializer(Int.serializer()), clean).derEncoded

            // Fault (B): equals/hashCode nevertheless collapse them.
            (decoded == clean) shouldBe false
            hashSetOf(decoded, clean).size shouldBe 2
        }

        /*
         * lenientset_equals_reencode_divergence
         *
         * BUG: LenientSet.equals/hashCode compare `elements.toSet()` and therefore ignore exactly
         * the duplicates and wire order that deserialize deliberately retains and serialize
         * re-emits. An instance the library's OWN toValidatedSet() rejects as an invalid SET
         * compares equal to — and hash-collapses with — its clean counterpart, desynchronising
         * any ==/hash-based validation gate from the bytes that are actually emitted.
         *
         * TRIGGER: SET { 2, 1, 2 } decoded vs LenientSet(setOf(1, 2)). Control (A) shows they
         * really are different: only one of them survives toValidatedSet(), and they re-encode
         * to different bytes.
         */
        "lenientset_equals_reencode_divergence" {
            val serializer = LenientSet.Serializer(Int.serializer())
            val duplicated = DER.decodeFromByteArray(serializer, "3109020102020101020102".hexToByteArray())
            val clean = LenientSet(linkedSetOf(1, 2))

            // Control (A): they are genuinely different objects.
            shouldThrow<at.asitplus.awesn1.Asn1Exception> { duplicated.toValidatedSet() }
            clean.toValidatedSet() shouldBe setOf(1, 2)
            DER.encodeToTlv(serializer, duplicated).derEncoded.toHexString() shouldNotBe
                    DER.encodeToTlv(serializer, clean).derEncoded.toHexString()

            // Fault (B): equality and hashing say otherwise.
            (duplicated == clean) shouldBe false
            hashSetOf<LenientSet<Int>>(duplicated, clean).size shouldBe 2
        }

        /*
         * lenientset_crossformat_illegal_state_bypass
         *
         * BUG: LenientSet.Serializer.deserialize sets preserveWireOrder = true without checking
         * that the Decoder is the DER decoder. Untrusted JSON can therefore mint the wire-only
         * state — attacker-chosen member order plus duplicates — which serialize then re-emits
         * verbatim through the non-sorting descriptor branch as a non-canonical DER SET OF.
         *
         * TRIGGER: Json "[2, 1, 2]" -> DER must still be the canonical SET { 1, 2 }.
         */
        "lenientset_crossformat_illegal_state_bypass" {
            val serializer = LenientSet.Serializer(Int.serializer())
            val fromJson = Json.decodeFromString(serializer, "[2, 1, 2]")
            DER.encodeToTlv(serializer, fromJson).derEncoded.toHexString() shouldBe "3106020101020102"
        }

        /*
         * lenientset_programmatic_illegal_emission_v2
         *
         * BUG: LenientSet.Serializer.deserialize unconditionally sets preserveWireOrder = true,
         * no matter which codec drove it. The flag is meant to mark "these bytes came off the
         * wire, keep their malformed order". Round-tripping a PROGRAMMATIC set through JSON
         * therefore arms wire-order preservation, and the next DER encode emits a non-canonical
         * (and possibly duplicate-carrying) SET, violating DER SET OF rules.
         *
         * TRIGGER: LenientSet(linkedSetOf(2,1)) encodes canonically as [1,2] (control A); after a
         * JSON round trip the very same value encodes as [2,1] (B). And a JSON array "[1,1,2]" —
         * data that never touched a DER wire — yields a duplicate-element SET.
         */
        "lenientset_programmatic_illegal_emission_v2" {
            val serializer = LenientSet.Serializer(Int.serializer())
            val programmatic = LenientSet(linkedSetOf(2, 1))

            // Control (A): a programmatic set encodes canonically sorted: SET { 1, 2 }.
            val canonical = DER.encodeToTlv(serializer, programmatic).derEncoded
            canonical.toHexString() shouldBe "3106020101020102"

            // Fault (B1): a JSON round trip must not change the emitted DER.
            val jsonRoundTripped = Json.decodeFromString(serializer, Json.encodeToString(serializer, programmatic))
            DER.encodeToTlv(serializer, jsonRoundTripped).derEncoded.toHexString() shouldBe canonical.toHexString()

            // Fault (B2): non-wire input must never produce a duplicate-element SET OF.
            val fromJsonDuplicates = Json.decodeFromString(serializer, "[1,1,2]")
            DER.encodeToTlv(serializer, fromJsonDuplicates).derEncoded.toHexString() shouldBe "3106020101020102"
        }

        /*
         * map_duplicate_key_collapse
         *
         * BUG: the losslessness guard in decodeSerializableValue keys on isKotlinSetDescriptor
         * only, so Map descriptors are exempt. Duplicate wire keys decode last-wins into a
         * LinkedHashMap, silently deleting the earlier pair, and decode -> re-encode diverges
         * from the wire while remaining indistinguishable from a legitimate single-pair encoding.
         *
         * TRIGGER: SEQUENCE { ("k",1), ("k",2) }. Control: the identical duplicate shape decoded
         * into a Set IS rejected ("Duplicate elements cannot be decoded ... without data loss").
         */
        "map_duplicate_key_collapse" {
            // Control (A): Set enforces losslessness.
            shouldThrow<SerializationException> {
                DER.decodeFromByteArray(SetSerializer(Int.serializer()), "3106020101020101".hexToByteArray())
            }

            // Fault (B): Map does not.
            shouldThrow<SerializationException> {
                DER.decodeFromByteArray(
                    MapSerializer(String.serializer(), Int.serializer()),
                    "300c0c016b0201010c016b020102".hexToByteArray(),
                )
            }
        }
    }

    "collection elements" - {
        /*
         * nullable_collection_element_silent_drop
         *
         * BUG: under the default explicitNulls = false, DerEncoder.encodeSerializableValue simply
         * returns without appending when a null turns up at a position where omission is not a
         * representable state — a LIST element or a MAP value. Two distinct Kotlin values then
         * encode to identical DER, and the emitted map form cannot be decoded by the library at
         * all.
         *
         * TRIGGER: [1, null, 3] must not encode identically to [1, 3]; {1: null} must round-trip
         * or be rejected at encode time. Control: explicitNulls = true does the right thing.
         */
        "nullable_collection_element_silent_drop" {
            val listSerializer = ListSerializer(serializer<Int?>())

            // Control (A): explicitNulls = true keeps the null.
            val explicit = DER { explicitNulls = true }
            explicit.decodeFromByteArray(listSerializer, explicit.encodeToByteArray(listSerializer, listOf(1, null, 3))) shouldBe
                    listOf(1, null, 3)

            // Fault (B1): under the default config the null vanishes into an identical encoding.
            shouldThrow<SerializationException> {
                DER.encodeToByteArray(listSerializer, listOf(1, null, 3))
            }

            // Fault (B2): the emitted map form is not decodable by the library itself.
            val mapSerializer = MapSerializer(Int.serializer(), serializer<String?>())
            shouldThrow<SerializationException> {
                DER.encodeToByteArray(mapSerializer, mapOf(1 to null))
            }
        }
    }

    "scalars and strings" - {
        /*
         * decodevalue_valueclass_unsigned_signed_fallback
         *
         * BUG: DerDecoder.decodeValue's four unsigned-type checks test the RAW property
         * descriptor instead of the unwrapped effectiveDescriptor, so an unsigned type inside a
         * @JvmInline value class falls through to the SIGNED arms. Consequences both ways: a
         * negative DER INTEGER is silently accepted as the bit-mirrored unsigned maximum, and the
         * library's own canonical encoding of any upper-half unsigned value fails to decode.
         *
         * TRIGGER: INTEGER -1 into a UInt-backed value class (must be rejected, as it is for a
         * bare UInt — control A), and a round trip of 4_000_000_000u (must succeed).
         */
        "decodevalue_valueclass_unsigned_signed_fallback" {
            val minusOne = "30030201ff".hexToByteArray()

            // Control (A): the unwrapped UInt property rejects -1.
            shouldThrow<SerializationException> { DER.decodeFromByteArray<GlWithUInt>(minusOne) }

            // Fault (B1): the wrapped UInt property must reject it too.
            shouldThrow<SerializationException> { DER.decodeFromByteArray<GlWithUIntWrap>(minusOne) }

            // Fault (B2): the library must be able to read back its own encoding.
            val big = GlWithUIntWrap(GlUIntWrap(4_000_000_000u))
            DER.decodeFromByteArray<GlWithUIntWrap>(DER.encodeToByteArray(big)) shouldBe big
        }

        /*
         * decodestring_lenient_lossy_string_normalization
         *
         * BUG: DerDecoder.decodeString decoded TeletexString as UTF-8. Distinct Latin-1 bytes were
         * therefore normalized to replacement characters instead of retaining their values.
         *
         * TRIGGER: TeletexString 0xE9 vs 0xEA. BoringSSL's compatibility profile interprets these
         * as U+00E9 and U+00EA respectively.
         */
        "decodestring_lenient_lossy_string_normalization" {
            val wireE9 = "30031401e9".hexToByteArray()
            val wireEA = "30031401ea".hexToByteArray()

            // A Kotlin String property no longer admits TeletexString at all: it could not re-encode one,
            // so accepting it would rewrite the tag on the way out.
            shouldThrow<SerializationException> { DER.decodeFromByteArray<GlStringHolder>(wireE9) }

            // Declaring Asn1String keeps the type, and its content must still decode as Latin-1 rather than
            // being normalized to replacement characters.
            DER.decodeFromByteArray<GlAsn1StringHolder>(wireE9).s.value shouldBe "é"
            DER.decodeFromByteArray<GlAsn1StringHolder>(wireEA).s.value shouldBe "ê"
            DER.encodeToByteArray(DER.decodeFromByteArray<GlAsn1StringHolder>(wireE9))
                .contentEquals(wireE9) shouldBe true
        }

        /*
         * decodestring_nonutf8_stringtype_misdecode
         *
         * BUG: decodeString admits BMPString / UniversalString / TeletexString through its tag
         * gate but never branches on the tag: everything is read as UTF-8 through
         * Asn1String.value. A well-formed UTF-16BE BMPString "admin" decodes to ten codepoints
         * with interleaved NULs, and re-encoding silently rewrites the tag 0x1E -> 0x0C.
         *
         * TRIGGER: SEQUENCE { BMPString "admin" } = 30 0C 1E 0A 00 61 00 64 00 6D 00 69 00 6E.
         * Control: an OCTET STRING is correctly rejected by the same gate.
         */
        "decodestring_nonutf8_stringtype_misdecode" {
            // Control (A): the tag gate rejects OCTET STRING.
            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<GlStringHolder>("300404024142".hexToByteArray())
            }

            // Fault (B): BMPString content must never be misread as UTF-8, and must never be silently
            // re-tagged to 0x0C. A Kotlin String property rejects it outright...
            val bmp = "300c1e0a00610064006d0069006e".hexToByteArray()
            shouldThrow<SerializationException> { DER.decodeFromByteArray<GlStringHolder>(bmp) }

            // ...and the Asn1String spelling decodes the UTF-16BE content correctly and round-trips the tag.
            DER.decodeFromByteArray<GlAsn1StringHolder>(bmp).s.value shouldBe "admin"
            DER.encodeToByteArray(DER.decodeFromByteArray<GlAsn1StringHolder>(bmp)).contentEquals(bmp) shouldBe true
        }
    }
}
