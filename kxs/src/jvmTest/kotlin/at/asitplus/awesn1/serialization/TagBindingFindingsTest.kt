// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

/*
 * Tag-binding findings: the tag a model declares and the tag that reaches the wire disagree.
 *
 * The encoder resolves an implicit tag template through core's `withImplicitTag`, which silently forces the
 * CONSTRUCTED bit to zero on primitives, while decode-side validation rebuilds the expected tag verbatim from the
 * same annotation. Nothing rejects the contradiction, so the format emits DER its own decoder refuses. The rest of
 * this suite is the mirror image: tag checks that are documented but never actually fire.
 *
 * Each case asserts the CORRECT (post-fix) behaviour, so it FAILS while the defect is present. Where the original
 * reproducer had an A/B shape ("this spelling works, that spelling breaks"), the working leg is kept as an in-test
 * control marked `Control (A)`, so a failure cannot be blamed on a broken fixture. Test names are the finding ids
 * under `findings/<harness>/submitted_humanreadable`.
 */

package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1OctetString
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Contextual
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.serializer

@OptIn(ExperimentalSerializationApi::class, ExperimentalStdlibApi::class)
val SerializationTagBindingFindings by matrixSuite {
    "CONSTRUCTED bit contradictions" - {
        /*
         * bytearray_constructed_tag_dropped_own_output_rejected
         *
         * BUG: for a byte-array property carrying constructed = CONSTRUCTED, DerEncoder delegates
         * to core withImplicitTag, which silently FORCES the constructed bit to zero on
         * primitives — while decode's validateAndResolveImplicitTagOverride builds the expected
         * tag verbatim from the same template and demands A1. The encoder emits 81, its decoder
         * demands A1: the model can never round-trip and nothing rejects it at encode time.
         *
         * TRIGGER: encode OctetConstructed(byteArrayOf(9, 9)) -> 30 04 81 02 09 09 and decode it
         * back. Control: the PRIMITIVE template round-trips.
         */
        "bytearray_constructed_tag_dropped_own_output_rejected" {
            // Control (A): a PRIMITIVE template round-trips.
            val ok = GlOctetPrimitive(byteArrayOf(9, 9))
            DER.decodeFromByteArray<GlOctetPrimitive>(DER.encodeToByteArray(ok)) shouldBe ok

            // Fault (B): the CONSTRUCTED template encodes but can never be decoded.
            val broken = GlOctetConstructed(byteArrayOf(9, 9))
            DER.decodeFromByteArray<GlOctetConstructed>(DER.encodeToByteArray(broken)) shouldBe broken
        }

        /*
         * constructed_tag_template_primitive_valued_silently_undecodable
         *
         * BUG: the generalisation of the byte-array case above — encode strips CONSTRUCTED from
         * the template for ANY primitive-valued property while decode demands it verbatim, and
         * nothing rejects the contradictory annotation. No wire form can ever satisfy the model:
         * the encoder's own 30 05 80 03 01 02 03 fails the tag check, and the schema-conforming
         * 30 07 A0 05 04 03 01 02 03 fails with "Asn1ExplicitlyTagged cannot be reinterpreted as
         * Asn1Primitive".
         *
         * TRIGGER: round-trip ConstructedTaggedBytes([1,2,3]) and, for the Int shape,
         * ConstructedTaggedInt(7).
         */
        "constructed_tag_template_primitive_valued_silently_undecodable" {
            val bytes = GlConstructedTaggedBytes(byteArrayOf(1, 2, 3))
            DER.decodeFromByteArray<GlConstructedTaggedBytes>(DER.encodeToByteArray(bytes)) shouldBe bytes

            val int = GlConstructedTaggedInt(7)
            DER.decodeFromByteArray<GlConstructedTaggedInt>(DER.encodeToByteArray(int)) shouldBe int
        }

        /*
         * enum_constructed_bit_roundtrip_v2
         *
         * BUG: the enum flavour of the constructed-bit asymmetry. encodeEnum applies a
         * CONSTRUCTED template to Asn1.Enumerated, which can only ever emit 82, while
         * validateAndResolveImplicitTagOverride demands A2. Neither the encoder's own output nor
         * any well-formed A2 wire can satisfy the model, and nothing rejects the annotation.
         *
         * TRIGGER: round-trip ConstructedHost(Mode.OFF).
         */
        "enum_constructed_bit_roundtrip_v2" {
            val value = GlConstructedEnumHost(GlMode.OFF)
            DER.decodeFromByteArray<GlConstructedEnumHost>(DER.encodeToByteArray(value)) shouldBe value
        }

        /*
         * primitive_constructed_hint_structure_undecodable
         *
         * BUG: finalizeElement never validates a constructed = PRIMITIVE override against the
         * property's STRUCTURE kind, so the encoder emits a BER-invalid primitive-tagged TLV whose
         * content is a concatenated child encoding. Its own typed decoder rejects that
         * ("Expected an ASN.1 structure ... but got Asn1Primitive"), and the conformant
         * constructed encoding a standards-compliant peer would send is rejected too.
         *
         * TRIGGER: @Asn1Tag(0, CONTEXT_SPECIFIC, PRIMITIVE) on a nested structure property.
         * Control: the CONSTRUCTED variant round-trips.
         */
        "primitive_constructed_hint_structure_undecodable" {
            // Control (A): CONSTRUCTED works.
            val ok = GlConsTaggedHolder(GlInner(5))
            DER.decodeFromByteArray<GlConsTaggedHolder>(DER.encodeToByteArray(ok)) shouldBe ok

            // Fault (B): PRIMITIVE on a structure is silently accepted and never decodable.
            val broken = GlPrimTaggedHolder(GlInner(5))
            DER.decodeFromByteArray<GlPrimTaggedHolder>(DER.encodeToByteArray(broken)) shouldBe broken
        }

        /*
         * octetwrapper_retag_primitive_leak_v2
         *
         * BUG: requireAsn1ExplicitWrapperTag returns early for every non-ExplicitlyTagged
         * descriptor, so an OctetStringEncapsulated property with a property-level tag override
         * whose constructed bit is left at INFER silently inherits the wrapper class's PRIMITIVE
         * bit. Structure content is then emitted under a primitive tag (80) that the library's
         * own decoder always rejects.
         *
         * TRIGGER: @Asn1Tag(0, CONTEXT_SPECIFIC) on OctetStringEncapsulated<Int>; encode emits
         * 30 05 80 03 02 01 05. Control: pinning constructed = CONSTRUCTED round-trips.
         */
        "octetwrapper_retag_primitive_leak_v2" {
            // Control (A): the CONSTRUCTED-pinned variant round-trips.
            val pinned = GlHostRetaggedConstructed(OctetStringEncapsulated(5))
            DER.decodeFromByteArray<GlHostRetaggedConstructed>(DER.encodeToByteArray(pinned)) shouldBe pinned

            // Fault (B): the INFER variant leaks the wrapper's PRIMITIVE bit.
            val infer = GlHostRetaggedInfer(OctetStringEncapsulated(5))
            DER.decodeFromByteArray<GlHostRetaggedInfer>(DER.encodeToByteArray(infer)) shouldBe infer
        }
    }

    "declared tags dropped on encode" - {
        /*
         * encodeenum_inline_tag_dropped
         *
         * BUG: enum encoding never reaches beginStructure, and encodeEnum ignores the
         * effectiveTagTemplate that encodeSerializableValue already computed. The class-level
         * @Asn1Tag of an enum-backed inline value class is therefore silently stripped on encode
         * while the decoder still demands it.
         *
         * TRIGGER: a value class @Asn1Tag(7, APPLICATION) wrapping an enum encodes as bare
         * ENUMERATED (0a 01 01) instead of 47 01 01, and the decoder rejects the encoder's own
         * output. Control: the untagged value class round-trips.
         */
        "encodeenum_inline_tag_dropped" {
            // Control (A): no class tag, no problem.
            val plain = GlPlainHolderHost(GlPlainEnumHolder(GlMode.ON), 5)
            DER.decodeFromByteArray<GlPlainHolderHost>(DER.encodeToByteArray(plain)) shouldBe plain

            // Fault (B): the declared APPLICATION 7 tag is dropped on encode.
            val tagged = GlTaggedHolderHost(GlTaggedEnumHolder(GlMode.ON), 5)
            DER.encodeToByteArray(tagged).toHexString() shouldBe "300647010102 0105".replace(" ", "")
            DER.decodeFromByteArray<GlTaggedHolderHost>(DER.encodeToByteArray(tagged)) shouldBe tagged
        }

        /*
         * inline_declared_leading_tags_dropped
         *
         * BUG: possibleBaseLeadingTags recurses through an inline value class BEFORE consulting
         * serializer-declared leading tags (withAsn1LeadingTags), so a value-class-backed custom
         * serializer's declared tag set is dropped. The ambiguity checker then certifies a
         * genuinely ambiguous layout, and decode nullifies the property WITHOUT consuming its
         * element — which shifts into the following property.
         *
         * TRIGGER: P4(t = Token(7)) encodes to SEQ{ UTF8 "7" } and decodes back as
         * P4(t = null, note = "7"). Control: the same layout with a non-inline delegate is
         * correctly rejected as "Ambiguous ASN.1 layout".
         */
        "inline_declared_leading_tags_dropped" {
            val der = DER { encodeDefaults = false }
            val value = GlP4(GlToken(7))
            der.decodeFromByteArray<GlP4>(der.encodeToByteArray(value)) shouldBe value
        }

        /*
         * derenv_rawtag_contextual_bypass
         *
         * BUG: requireNoAsn1TagOnRawElement only recognises a raw element by the
         * ASN1_DESCRIPTOR_ELEMENT_TREE serial name. A `@Contextual val e: Asn1Element` property
         * resolves to kotlinx' ContextualSerializer placeholder descriptor, so the guard
         * early-returns and the raw element is re-tagged via withImplicitTag — which force-clears
         * the CONSTRUCTED bit on a primitive. The emitted DER contradicts the declared @Asn1Tag
         * and the library's own decoder rejects it.
         *
         * TRIGGER: same @Asn1Tag(..., CONSTRUCTED) on a raw Asn1Element, once plain (rejected,
         * control A) and once with @Contextual (silently accepted, B). Both spellings must be
         * rejected identically.
         */
        "derenv_rawtag_contextual_bypass" {
            val octet = Asn1.OctetString(byteArrayOf(1, 2))

            // Control (A): the plain spelling is rejected by the design guard.
            shouldThrow<SerializationException> {
                DER.encodeToByteArray(DsRawTagPlain(octet))
            }

            // Fault (B): @Contextual bypasses the very same guard and emits 30 04 80 02 01 02,
            // i.e. a PRIMITIVE [0] where the annotation declared CONSTRUCTED [0] (=A0).
            shouldThrow<SerializationException> {
                DER.encodeToByteArray(DsRawTagContextual(octet))
            }
        }
    }

    "tag checks that never fire" - {
        /*
         * asn1octetstring_any_tag_acceptance
         *
         * BUG: the ELEMENT_TREE arm of DerDecoder.decodeSerializableValue returns before the
         * default-tag enforcement block. For an un-annotated Asn1OctetString property expectedTag
         * is null, so NOTHING checks the wire tag: any primitive element (INTEGER, BOOLEAN, UTC
         * TIME, a context-specific primitive...) is accepted as an OCTET STRING and its original
         * tag is destroyed.
         *
         * TRIGGER: SEQUENCE { INTEGER 5 } fed to a model declaring an Asn1OctetString.
         * Control: the identical wire IS rejected for a ByteArray-typed property.
         */
        "asn1octetstring_any_tag_acceptance" {
            val integerWhereOctetStringDeclared = "3003020105".hexToByteArray()

            // Control (A): the ByteArray shape enforces the OCTET STRING tag.
            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<GlByteArrayHolder>(integerWhereOctetStringDeclared)
            }

            // Fault (B): the Asn1OctetString shape accepts any primitive tag.
            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<GlOctetStringHolder>(integerWhereOctetStringDeclared)
            }
        }

        /*
         * asn1tag_infer_class_ambiguity_mispredict
         *
         * BUG: applyImplicitTagOverride in AmbiguityChecks substitutes the BASE tag's class for
         * Asn1Tag.Class.INFER, while the encoder forces CONTEXT_SPECIFIC and decode-side
         * validation accepts any class. The ambiguity checker therefore predicts
         * [UNIVERSAL:5] for property `a` and [CONTEXT:5] for `b` and certifies the layout as
         * unambiguous — but on the wire both are [CONTEXT:5] and the elements misbind.
         *
         * TRIGGER: encode T1A(a = "ab") and decode the library's own output back. It comes back
         * as T1A(a = null, b = 24930): the string payload was reinterpreted as an INTEGER in the
         * sibling property. Control: the identical layout with explicit CONTEXT classes is
         * correctly rejected as "Ambiguous ASN.1 layout".
         */
        "asn1tag_infer_class_ambiguity_mispredict" {
            // Control (A): without INFER the guard fires.
            shouldThrow<SerializationException> {
                DER.encodeToByteArray(GlBothContext(a = "ab"))
            }

            // Fault (B): with INFER the same collision is certified and silently misbinds.
            val value = GlInferClass(a = "ab")
            DER.decodeFromByteArray<GlInferClass>(DER.encodeToByteArray(value)) shouldBe value
        }
    }
}
