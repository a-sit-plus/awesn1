// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

/*
 * Null and optional findings: absence and presence are not distinguishable on the wire.
 *
 * A nullable property needs a sentinel the decoder can tell apart from a real value, and an omittable one needs a
 * presence rule that predicts the tags its type actually emits. Both go wrong here: sentinels collide with legitimate
 * values, and presence inference declares a present element absent - which leaves it unconsumed, so it mis-binds into
 * the NEXT property and the error surfaces against an innocent field.
 *
 * Each case asserts the CORRECT (post-fix) behaviour, so it FAILS while the defect is present. Where the original
 * reproducer had an A/B shape ("this spelling works, that spelling breaks"), the working leg is kept as an in-test
 * control marked `Control (A)`, so a failure cannot be blamed on a broken fixture. Test names are the finding ids
 * under `findings/<harness>/submitted_humanreadable`.
 */

package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.Asn1OctetString
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encodeToByteArray

@OptIn(ExperimentalSerializationApi::class, ExperimentalStdlibApi::class)
val SerializationNullAndOptionalFindings by matrixSuite {
    "null sentinel collisions" - {
        /*
         * null_roundtrip_constructed_tag
         *
         * BUG: DerEncoder.encodeNull writes the PRIMITIVE Asn1.Null() and applies the implicit tag
         * via withImplicitTag, which force-clears CONSTRUCTED on primitives — so a field declared
         * @Asn1Tag(0, CONSTRUCTED) emits `30 02 80 00` (primitive [0]). The decoder, however,
         * resolves the expected tag from the annotation (A0, constructed) BEFORE it looks at the
         * null branch, and throws Asn1TagMismatchException. Encode(null) produces bytes the same
         * library cannot decode.
         *
         * TRIGGER: encode null, decode it back. Control: the non-null value round-trips fine, so
         * the break is null-specific.
         */
        "null_roundtrip_constructed_tag" {
            val der = DER { explicitNulls = true }

            // Control (A): non-null round-trips.
            val nonNull = DsConstTaggedNullable(DsInner(7))
            der.decodeFromDer<DsConstTaggedNullable>(der.encodeToByteArray(nonNull)) shouldBe nonNull

            // Fault (B): the encoder's own null encoding is rejected by its own decoder.
            val nulled = DsConstTaggedNullable(null)
            der.decodeFromDer<DsConstTaggedNullable>(der.encodeToByteArray(nulled)) shouldBe nulled
        }

        /*
         * null_sentinel_data_swallow
         *
         * BUG: the constructed-bit null branch in DerDecoder.decodeSerializableValue tests only
         * `!element.tag.isConstructed`. It never requires zero-length content or a real NULL
         * sentinel, so ANY primitive element carrying the field's implicit tag is read as null and
         * its whole payload is silently discarded — structurally valid DER that hides bytes from
         * this parser while other parsers see them.
         *
         * TRIGGER: 30 08 81 03 01 02 03 82 01 09 — a PRIMITIVE [1] with three content bytes where
         * the model declares a nullable List<Int>. The encoder only ever emits `81 00` for null
         * (control A) and `A1 ...` for a value, so a primitive [1] WITH content is not a null
         * sentinel and must be rejected rather than swallowed.
         */
        "null_sentinel_data_swallow" {
            val der = DER { explicitNulls = true }

            // Control (A): the shapes the encoder actually emits.
            der.encodeToByteArray(DsItemModel(null, 9)).toHexString() shouldBe "30058100820109"
            der.encodeToByteArray(DsItemModel(listOf(7), 9)).toHexString() shouldBe "3008a103020107820109"

            // Fault (B): a primitive [1] carrying 01 02 03 must not decode as `items = null`.
            val smuggled = byteArrayOf(0x30, 0x08, 0x81.toByte(), 0x03, 0x01, 0x02, 0x03, 0x82.toByte(), 0x01, 0x09)
            shouldThrow<SerializationException> { der.decodeFromDer<DsItemModel>(smuggled) }
        }

        /*
         * inline_nullable_null_sentinel_undecodable
         *
         * BUG: the inline fast path in decodeSerializableValue returns before the tryConsumeEncodedNull
         * block, so the tagged null sentinel that encodeNull emits for a nullable value-class
         * property (30 02 85 00) reaches the primitive decode path as a zero-length Int and is
         * rejected. The encoder's own output is unconditionally undecodable.
         *
         * TRIGGER: explicitNulls = true, encode Holder(null), decode it back.
         * Control: the raw NULL shape (05 00), which the encoder never emits, does decode.
         */
        "inline_nullable_null_sentinel_undecodable" {
            val der = DER { explicitNulls = true }

            // Control (A): the raw-NULL shape decodes as null.
            der.decodeFromByteArray<GlWrappedIntHolder>("30020500".hexToByteArray()) shouldBe
                    GlWrappedIntHolder(null)

            // Fault (B): the encoder's own sentinel does not.
            val nulled = GlWrappedIntHolder(null)
            der.decodeFromByteArray<GlWrappedIntHolder>(der.encodeToByteArray(nulled)) shouldBe nulled
        }

        /*
         * nullable_raw_element_null_sentinel_collision
         *
         * BUG: a raw-element (ELEMENT_TREE) property holding the VALUE Asn1.Null() encodes to
         * exactly the same bytes as the property-null SENTINEL (05 00), and
         * analyzeAsn1NullableNullEncoding never flags this because it requires a tag template.
         * The encoder's own output is therefore rejected outright under the default config, and
         * silently read as property-null under explicitNulls = true.
         *
         * TRIGGER: round-trip RawNullableHolder(Asn1.Null()). Control: any non-NULL raw element
         * round-trips.
         */
        "nullable_raw_element_null_sentinel_collision" {
            // Control (A): a non-NULL raw element round-trips.
            val ok = GlRawNullableHolder(Asn1.Int(1))
            DER.decodeFromByteArray<GlRawNullableHolder>(DER.encodeToByteArray(ok)) shouldBe ok

            // Fault (B): the NULL element collides with the null sentinel.
            val nullElement = GlRawNullableHolder(Asn1.Null())
            DER.decodeFromByteArray<GlRawNullableHolder>(DER.encodeToByteArray(nullElement)) shouldBe nullElement
        }

        /*
         * nullsentinel_emptycoll_primitive_tag
         *
         * BUG: asn1BaseCanEncodeEmptyContent does not treat LIST/MAP/CLASS/OBJECT as
         * empty-content-capable when the tag template forces constructed = false. The explicit
         * null sentinel and an EMPTY collection then encode to byte-identical DER, and the empty
         * collection silently decodes back as Kotlin null.
         *
         * TRIGGER: with @Asn1Tag(0, PRIMITIVE) on a List<Int>?, L1(null, 5) and
         * L1(emptyList(), 5) both encode to 30 05 80 00 02 01 05. Control: the same template on
         * a String? IS rejected with "Ambiguous ASN.1 null encoding".
         */
        "nullsentinel_emptycoll_primitive_tag" {
            val der = DER { explicitNulls = true }

            // Control (A): the guard exists for primitive-kind bases.
            shouldThrow<SerializationException> { der.encodeToByteArray(GlPrimitiveNullSentinel(null, 5)) }

            // Fault (B): for structure kinds null and empty are indistinguishable.
            der.encodeToByteArray(GlListNullSentinel(null, 5)).toHexString() shouldNotBe
                    der.encodeToByteArray(GlListNullSentinel(emptyList(), 5)).toHexString()
        }

        /*
         * octetwrapper_null_payload_undecodable
         *
         * BUG: with a null OctetStringEncapsulated payload, encodeNull silently omits the child
         * and finalizeElement emits an empty-content PRIMITIVE OCTET STRING (04 00). The core
         * parser keeps that as a non-encapsulating Asn1OctetString, and DerDecoder.beginStructure
         * rejects it for the CLASS-kind wrapper descriptor: the library's own output can never be
         * read back.
         *
         * TRIGGER: round-trip Host(OctetStringEncapsulated<Int?>(null)) under the default config.
         * Control: a non-null payload round-trips.
         */
        "octetwrapper_null_payload_undecodable" {
            // Control (A): a non-null payload round-trips.
            val ok = GlHostNullableInt(OctetStringEncapsulated(7))
            DER.decodeFromByteArray<GlHostNullableInt>(DER.encodeToByteArray(ok)) shouldBe ok

            // Fault (B): the null payload emits 30 02 04 00, which never decodes.
            val nullPayload = GlHostNullableInt(OctetStringEncapsulated(null))
            DER.decodeFromByteArray<GlHostNullableInt>(DER.encodeToByteArray(nullPayload)) shouldBe nullPayload
        }
    }

    "presence inference" - {
        /*
         * nullable_enum_presence_tag_int_vs_enumerated
         *
         * BUG: possibleBaseLeadingTags never maps SerialKind.ENUM to the ENUMERATED tag (0x0A)
         * that encodeEnum and the enum decode fast path actually use. The nullable/omittable
         * presence check therefore classifies EVERY non-null enum value as absent: the property
         * is nullified, its element is left unconsumed and the message is rejected — including
         * the library's own encodings.
         *
         * TRIGGER: encode JustEnum(MyEnum.A) -> 30 03 0A 01 00 and decode it back under the
         * default config. Control: the same bytes decode under explicitNulls = true.
         */
        "nullable_enum_presence_tag_int_vs_enumerated" {
            val ownOutput = DER.encodeToByteArray(GlJustEnum(GlMode.OFF))

            // Control (A): explicitNulls = true reads the very same bytes.
            DER { explicitNulls = true }.decodeFromByteArray<GlJustEnum>(ownOutput) shouldBe GlJustEnum(GlMode.OFF)

            // Fault (B): the default config cannot read the library's own output.
            DER.decodeFromByteArray<GlJustEnum>(ownOutput) shouldBe GlJustEnum(GlMode.OFF)
        }

        /*
         * setdescriptor_nullable_setof_owntag_reject
         *
         * BUG: asNamedSetDescriptor never surfaces SET-ness through the descriptor's `kind` (it
         * stays LIST from the ListSerializer delegate), so the kind-based tag inference in
         * possibleBaseLeadingTags expects SEQUENCE for SET OF properties. The nullable-omission
         * branch then nullifies a POPULATED property and leaves its element unconsumed.
         *
         * TRIGGER: TailLenient(1, LenientSet(setOf(2, 1))) — encode then decode. The bytes are
         * byte-identical to the non-nullable variant, which decodes fine (control A).
         */
        "setdescriptor_nullable_setof_owntag_reject" {
            val nonNullable = GlTailNonNull(1, LenientSet(linkedSetOf(2, 1)))
            val encoded = DER.encodeToByteArray(nonNullable)

            // Control (A): the non-nullable variant round-trips those exact bytes.
            DER.decodeFromByteArray<GlTailNonNull>(encoded).id shouldBe 1

            // Fault (B): making the property nullable makes the identical bytes undecodable.
            DER.decodeFromByteArray<GlTailLenient>(encoded).exts shouldNotBe null
        }
    }

    "ambiguity gate" - {
        /*
         * gate_certifies_undecodable_defaulted_optional_layouts
         *
         * BUG: DerDecoder.decodeElementIndex derives `couldBeAbsent` from NULLABILITY only, so a
         * non-nullable kotlinx-OPTIONAL (defaulted) property has no tag-based presence
         * resolution: it unconditionally binds the next wire element and then fails tag
         * validation. Meanwhile ensureNoAsn1AmbiguousOptionalLayout certifies exactly these
         * layouts as unambiguous, so the X.690-conformant default-omitted form — and the
         * library's own encodeDefaults = false output — are rejected.
         *
         * TRIGGER: SEQUENCE { SEQUENCE{5}, [1] SEQUENCE{9} } with the middle default omitted.
         * Control: the nullable-optional variant decodes the same bytes fine.
         */
        "gate_certifies_undecodable_defaulted_optional_layouts" {
            val optOmitted = "300a3003020105a103020109".hexToByteArray()

            // Control (A): making `opt` nullable rather than defaulted decodes the same wire.
            DER.decodeFromByteArray<GlModelNullableOpt>(optOmitted) shouldBe
                    GlModelNullableOpt(GlInner(5), null, GlInner(9))

            // Fault (B): the defaulted variant rejects the DER-mandated omitted form.
            DER.decodeFromByteArray<GlModelDefaultedOpt>(optOmitted) shouldBe
                    GlModelDefaultedOpt(GlInner(5), GlInner(7), GlInner(9))
        }

        /*
         * gate_skips_nullable_defaulted_fields_under_explicit_nulls
         *
         * REGRESSION: a property can be omitted from the wire for two independent reasons —
         * it is nullable and nulls are omitted, or it is kotlinx-OPTIONAL and encodeDefaults is
         * false. The layout gate must treat a field as omittable if EITHER holds, because
         * ensureNoAsn1AmbiguousOptionalLayout never sees encodeDefaults and so cannot rule the
         * second reason out. A presence model that lets nullability shadow the defaulted axis
         * certifies a layout whose fields can still both vanish.
         *
         * TRIGGER: two nullable defaulted Int properties sharing @Asn1Tag(5) under
         * explicitNulls = true and encodeDefaults = false. Int cannot encode empty content, so the
         * per-field null-encoding guard does not fire and the layout gate is the only check left.
         * Control (A): the same layout under the default explicitNulls = false, where the nullable
         * axis alone already makes both fields omittable.
         */
        "gate_skips_nullable_defaulted_fields_under_explicit_nulls" {
            // Control (A): explicitNulls = false — both fields omittable via the nullable axis.
            shouldThrow<SerializationException> {
                DER.encodeToByteArray(GlNullableDefaultedCollision(a = 1))
            }.message shouldContain "Ambiguous ASN.1 layout"

            // Fault (B): explicitNulls = true — the nullable axis no longer omits, but
            // encodeDefaults = false still can, so the collision is unchanged and must be caught.
            val der = DER { explicitNulls = true; encodeDefaults = false }
            shouldThrow<SerializationException> {
                der.encodeToByteArray(GlNullableDefaultedCollision(a = 1))
            }.message shouldContain "Ambiguous ASN.1 layout"
        }

        /*
         * descriptor_validation_uses_identity_for_deduplication
         *
         * REGRESSION: structural SerialDescriptor equality is annotation-blind. Validation must
         * therefore deduplicate by identity, or two @SerialName("Shared") descriptors that differ
         * only in their @Asn1Tag annotations collapse and the ambiguous second type is never checked.
         *
         * TRIGGER: RootBoth(a = Disambiguated, b = Ambiguous). Decoding it must raise the same
         * "Ambiguous ASN.1 layout" the ambiguous type raises on its own (control A).
         */
        "descriptor_validation_uses_identity_for_deduplication" {
            // Control (A): the ambiguous type alone is rejected.
            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<GlAmbiguous>("3003020108".hexToByteArray())
            }

            // Fault (B): behind a structurally-equal sibling the guard is skipped and the
            // attacker's INTEGER 8 silently binds to `opt` instead of `req`.
            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<GlRootBoth>("300d30068001058101063003020108".hexToByteArray())
            }
        }
    }
}
