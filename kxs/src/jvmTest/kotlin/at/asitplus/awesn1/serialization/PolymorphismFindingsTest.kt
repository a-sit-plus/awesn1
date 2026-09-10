// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

/*
 * Polymorphism findings: the discriminator written is not the discriminator dispatched on.
 *
 * Open polymorphism keys decode on a subtype's leading tag or its OID. Encode-side tag templates, SET sorting and
 * registration are none of them reconciled with that table, so the format can emit framing it cannot dispatch, or -
 * worse - framing that dispatches to a DIFFERENT registered subtype with no exception anywhere.
 *
 * Each case asserts the CORRECT (post-fix) behaviour, so it FAILS while the defect is present. Where the original
 * reproducer had an A/B shape ("this spelling works, that spelling breaks"), the working leg is kept as an in-test
 * control marked `Control (A)`, so a failure cannot be blamed on a broken fixture. Test names are the finding ids
 * under `findings/<harness>/submitted_humanreadable`.
 */

package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Encodable
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.unaryPlus
import at.asitplus.awesn1.readOid
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.jvm.JvmInline
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.serializer

@OptIn(ExperimentalSerializationApi::class, ExperimentalStdlibApi::class)
val SerializationPolymorphismFindings by matrixSuite {
    "tag-discriminated dispatch" - {
        /*
         * bytag_declared_leadingtags_ignored_on_encode
         *
         * BUG: leadingTags declared in the polymorphicByTag DSL feed decode dispatch and
         * ambiguity planning only — they are never used as an encode-side tag template and never
         * reconciled with what the subtype serializer actually emits. Registering
         * ApprovedRequest under SET while its serializer emits SEQUENCE therefore produces wire
         * the same dispatch table binds to the OTHER subtype.
         *
         * TRIGGER: encode ApprovedRequest(42) and decode it back — it returns RejectedRequest(42).
         * Either registration should be rejected, or encode must honour the declared tag.
         */
        "bytag_declared_leadingtags_ignored_on_encode" {
            val der = DER {
                serializersModule = SerializersModule {
                    polymorphicByTag(GlRequest::class, serialName = "GlRequest") {
                        subtype<GlApprovedRequest>(Asn1Element.Tag.SET)
                        subtype<GlRejectedRequest>(Asn1Element.Tag.SEQUENCE)
                    }
                }
            }

            val approved: GlRequest = GlApprovedRequest(42)
            der.decodeFromByteArray<GlRequest>(der.encodeToByteArray(approved)) shouldBe approved
        }

        /*
         * bytag_poly_inherited_tag_undecodable
         *
         * BUG: the encoder deliberately stamps a property-level @Asn1Tag onto the emitted
         * open-polymorphic subtype element, but Asn1TagDiscriminatedOpenPolymorphicSerializer
         * .serializerForDecode dispatches on an EXACT match of the raw leading wire tag and never
         * accounts for that inherited tag. The encoder emits framing its own decoder can never
         * dispatch.
         *
         * TRIGGER: Holder(@Asn1Tag(1) poly) with a value-class subtype encodes to 30 03 81 01 05;
         * decoding it throws "No registered open-polymorphic subtype ... CONTEXT_SPECIFIC 1".
         * Control: the same property without the @Asn1Tag round-trips.
         */
        "bytag_poly_inherited_tag_undecodable" {
            val der = DER {
                serializersModule = SerializersModule {
                    polymorphicByTag(GlTagB::class, serialName = "GlTagB") {
                        subtype<GlTagBInt>()
                        subtype<GlTagBStr>()
                    }
                }
            }

            // Control (A): untagged polymorphic property round-trips.
            val untagged = GlUntaggedPolyHolder(GlTagBInt(5))
            der.decodeFromByteArray<GlUntaggedPolyHolder>(der.encodeToByteArray(untagged)) shouldBe untagged

            // Fault (B): the inherited property tag makes the output undecodable.
            val tagged = GlTaggedPolyHolder(GlTagBInt(5))
            der.decodeFromByteArray<GlTaggedPolyHolder>(der.encodeToByteArray(tagged)) shouldBe tagged
        }

        /*
         * bytag_registered_leadingtags_encode_ignored_silent_misbind
         *
         * BUG: Asn1OpenPolymorphismByTagBuilder.subtype accepts explicit leadingTags without ever
         * checking them against the tags the registered serializer emits. Registering Circle
         * (whose descriptor emits SEQUENCE) under Asn1Element.Tag.INT builds silently; encode
         * emits SEQUENCE, and decode dispatches that SEQUENCE to the OTHER subtype (Square).
         * encode -> decode is provably not the identity.
         *
         * TRIGGER: encode Circle(3) and decode it back — Square(side = 3) comes out.
         */
        "bytag_registered_leadingtags_encode_ignored_silent_misbind" {
            val der = DER {
                serializersModule = SerializersModule {
                    polymorphicByTag(GlShape::class, serialName = "GlShape") {
                        subtype(GlCircle.serializer(), setOf(Asn1Element.Tag.INT)) { it is GlCircle }
                        subtype<GlSquare>()
                    }
                }
            }

            val circle: GlShape = GlCircle(3)
            der.decodeFromByteArray<GlShape>(der.encodeToByteArray(circle)) shouldBe circle
        }

        /*
         * openpoly_property_tag_replaces_discriminator
         *
         * BUG: an inherited property/inline @Asn1Tag template crossing a tag-discriminated
         * open-polymorphic dispatch is applied to the emitted arm without ever being checked
         * against the arm's registered leading tags. The tag that IS the discriminator is
         * therefore replaced: the output is either undecodable, or — worse — dispatches to a
         * different registered subtype whose leading tag happens to match.
         *
         * TRIGGER: OpenTaggedHolder(OpenStruct(5)) encodes to 30 05 A0 03 02 01 05, and decoding
         * fails to find any subtype for [0] CONSTRUCTED.
         */
        "openpoly_property_tag_replaces_discriminator" {
            val der = DER {
                serializersModule = SerializersModule {
                    polymorphicByTag(GlOpenBase2::class, serialName = "GlOpenBase2") {
                        subtype<GlOpenStruct>()
                        subtype<GlOpenPrim>()
                    }
                }
            }

            val value = GlOpenTaggedHolder(GlOpenStruct(5))
            der.decodeFromByteArray<GlOpenTaggedHolder>(der.encodeToByteArray(value)) shouldBe value
        }

        /*
         * openpoly_primitive_tag_asymmetry
         *
         * BUG: for a tag-discriminated open-polymorphic property carrying a property-level
         * @Asn1Tag, DerEncoder propagates that tag onto the primitive payload of an inline
         * value-class subtype (pendingBeginStructureTagTemplate). Decode dispatch, however, keys
         * purely on each subtype's NATURAL leading tag, so the emitted [0] tag matches no subtype:
         * the library cannot decode its own output, and every primitive-backed subtype collapses
         * onto the same wire tag.
         *
         * TRIGGER: encode Wrapper(OpenInt(7)) -> 30 03 80 01 07, then decode it back.
         * Control: the same subtype at top level (no property tag) round-trips fine.
         */
        "openpoly_primitive_tag_asymmetry" {
            val der = DER {
                serializersModule = SerializersModule {
                    polymorphicByTag(DsOpenByTag::class, serialName = "DsOpenByTag") {
                        subtype<DsOpenInt>()
                        subtype<DsOpenStr>()
                    }
                }
            }

            // Control (A): without a property tag the dispatch works.
            val bare: DsOpenByTag = DsOpenInt(7)
            der.decodeFromByteArray<DsOpenByTag>(der.encodeToByteArray(bare)) shouldBe bare

            // Fault (B): the property tag replaces the subtype tag, so decode finds no subtype.
            val wrapped = DsOpenWrapper(DsOpenInt(7))
            der.decodeFromDer<DsOpenWrapper>(der.encodeToByteArray(wrapped)) shouldBe wrapped

            // ...and both primitive subtypes would otherwise collapse onto leading tag [0].
            der.encodeToByteArray(DsOpenWrapper(DsOpenStr("hi")))[2] shouldNotBe
                    der.encodeToByteArray(DsOpenWrapper(DsOpenInt(7)))[2]
        }

        /*
         * openpoly_tagdispatch_wrapper_tag
         *
         * BUG: Asn1TagDiscriminatedOpenPolymorphicSerializer.serializerForDecode peeks the RAW
         * OUTER wire tag (peekCurrentElementTagOrNull) rather than the inner subtype's leading
         * tag. When the polymorphic property carries an @Asn1Tag wrapper — a documented pattern
         * that the OID backend handles correctly — the encoder emits A7 { A3 { ... } } and the
         * decoder dispatches on A7, which matches no registered subtype.
         *
         * TRIGGER: encode EnvTag(PolyA(1,2), 99) -> 30 0b a7 06 ... and decode it back.
         */
        "openpoly_tagdispatch_wrapper_tag" {
            val der = DER {
                serializersModule = SerializersModule {
                    polymorphicByTag(DsPoly::class, serialName = "DsPoly") { subtype<DsPolyA>() }
                }
            }

            // Control (A): unwrapped dispatch round-trips.
            val bare: DsPoly = DsPolyA(1, 2)
            der.decodeFromByteArray<DsPoly>(der.encodeToByteArray(bare)) shouldBe bare

            // Fault (B): the same value behind an @Asn1Tag wrapper property cannot be decoded.
            val wrapped = DsEnvTag(DsPolyA(1, 2), 99)
            der.decodeFromDer<DsEnvTag>(der.encodeToByteArray(wrapped)) shouldBe wrapped
        }

        /*
         * stale_inherited_openpoly_tag
         *
         * BUG: DerDecoder sets `inheritedOpenPolymorphicTag` for an open-polymorphic property and
         * never restores it (no try/finally, unlike the encoder's pendingBeginStructureTagTemplate).
         * The polymorphic property's tag therefore leaks onto EVERY subsequent non-primitive
         * property on the same structure level: the decoder rejects its own canonical output and
         * ACCEPTS attacker-retagged wire instead — a malleability hole.
         *
         * TRIGGER: Container(@Asn1Tag(0) ext: PolyOidBase, metadata: Metadata). The canonical
         * encoding must decode; the wire with metadata's 0x30 flipped to 0xA0 must not.
         */
        "stale_inherited_openpoly_tag" {
            val der = DER {
                serializersModule = SerializersModule {
                    polymorphicByOid(GlPolyOidBase::class, serialName = "GlPolyOidBase") {
                        subtype<GlSubInt>(GlSubInt)
                    }
                }
            }

            val value = GlContainer(GlSubInt(7), GlMetadata("hello"))
            val canonical = der.encodeToByteArray(value)

            // Fault (B1): the decoder must accept its own canonical output.
            der.decodeFromByteArray<GlContainer>(canonical) shouldBe value

            // Fault (B2): the retagged (non-conforming) wire must NOT be accepted.
            val retagged = canonical.copyOf().also { bytes ->
                val idx = bytes.indexOfLast { it == 0x30.toByte() }
                bytes[idx] = 0xA0.toByte()
            }
            shouldThrow<SerializationException> { der.decodeFromByteArray<GlContainer>(retagged) }
        }
    }

    "OID-discriminated dispatch" - {
        /*
         * byoid_aliased_oid_silent_narrowing_v2
         *
         * BUG: Asn1OidDiscriminatedDispatch.registrationForEncode picks an arm via a
         * subclass-inclusive `runtimeClass.isInstance` scan and never prefers the value's own
         * class registration. A subclass that INHERITS the base's `oid` property therefore
         * resolves to the BASE arm: it is encoded with the base serializer, all subclass-only
         * fields vanish and the discriminator OID silently changes — no exception anywhere.
         *
         * TRIGGER: encode GlVSub(1, 2) through the base-typed polymorphic serializer and decode
         * it back. Control: the base type itself round-trips.
         */
        "byoid_aliased_oid_silent_narrowing_v2" {
            val der = DER {
                serializersModule = SerializersModule {
                    polymorphicByOid(GlVRoot::class, serialName = "GlVRoot") {
                        subtype<GlVBase>(GlVBase)
                        subtype<GlVSub>(GlVSub)
                    }
                }
            }

            // Control (A): the base arm round-trips.
            val base: GlVRoot = GlVBase(1)
            der.decodeFromByteArray<GlVRoot>(der.encodeToByteArray(base)).shouldBeInstanceOf<GlVBase>()

            // Fault (B): the subclass is silently narrowed to the base (field b == 2 is dropped).
            val sub: GlVRoot = GlVSub(2)
            der.decodeFromByteArray<GlVRoot>(der.encodeToByteArray(sub))
                .shouldBeInstanceOf<GlVSub>().b shouldBe 2
        }

        /*
         * custom_oidselector_drop_misalignment
         *
         * BUG: a custom oidSelector may read the discriminator from ANY child, but
         * serializerForDecode sets the position-less `dropFirstChildInNextStructure` flag, so
         * beginStructure always discards child[0]. With a selector reading child[1] the marker
         * element is silently deleted, every payload binding shifts onto the discriminator, and
         * decode -> re-encode diverges from the wire.
         *
         * TRIGGER: SEQUENCE { INTEGER 7, OID <discriminator>, INTEGER 5 } with a child[1]
         * selector. Decoding must not silently drop the INTEGER 7 marker.
         */
        "custom_oidselector_drop_misalignment" {
            val der = DER {
                serializersModule = SerializersModule {
                    polymorphicByOid(
                        GlSelBase::class,
                        serialName = "GlSelBase",
                        oidSelector = { element ->
                            (element as? at.asitplus.awesn1.Asn1Structure)?.children?.getOrNull(1)
                                ?.let { it as? at.asitplus.awesn1.Asn1Primitive }
                                ?.takeIf { it.tag == Asn1Element.Tag.OID }
                                ?.let { runCatching { it.readOid() }.getOrNull() }
                        },
                    ) { subtype<GlSubOidExact>(GlSubOidExact) }
                }
            }

            val wire = "301c0201070614698192b2e2c8dbfcf294f58cc9b5f2ac87948247020105".hexToByteArray()
            // The selector API does not expose which child it consumed, so a non-leading
            // discriminator cannot be removed without shifting the subtype's fields.
            shouldThrow<SerializationException> { der.decodeFromByteArray<GlSelBase>(wire) }
        }

        /*
         * oid_discriminator_displaced_by_set_sorting
         *
         * BUG: DerEncoder.finalizeElement does not exempt the injected OID discriminator from
         * canonical SET sorting, so for a subtype whose descriptor is SET-family the discriminator
         * sorts to the LAST position. OID dispatch reads the FIRST child, so the emitted wire can
         * never be decoded back.
         *
         * TRIGGER: encode IdentifiableSet(setOf(1, 2)) through the OID-polymorphic base and
         * decode it back.
         */
        "oid_discriminator_displaced_by_set_sorting" {
            val der = DER {
                serializersModule = SerializersModule {
                    polymorphicByOid(GlOidA::class, serialName = "GlOidA") {
                        subtype<GlIdentifiableSet>(GlIdentifiableSet)
                    }
                }
            }

            val value: GlOidA = GlIdentifiableSet(linkedSetOf(1, 2))
            der.decodeFromByteArray<GlOidA>(der.encodeToByteArray(value)) shouldBe value
        }

        /*
         * oid_dispatch_dual_registration_discriminator_swap
         *
         * BUG: registering the SAME class as both an exact subtype and the catchAll is accepted
         * silently, and registrationForEncode never checks that the resolved arm's discriminator
         * convention matches the dispatch decision. On re-encode a value whose own `oid` property
         * carries an attacker-chosen OID misses the exact table, takes the CatchAll arm (which
         * injects no discriminator) and emits the ATTACKER's OID in the discriminator slot.
         *
         * TRIGGER: SEQ { OID 2.5.4.3, OID 1.3.99.77, INTEGER 7 } decoded and re-encoded — the
         * discriminator the registry dispatched on must not silently change.
         */
        "oid_dispatch_dual_registration_discriminator_swap" {
            val der = DER {
                serializersModule = SerializersModule {
                    polymorphicByOid(GlDualBase::class, serialName = "GlDualBase") {
                        subtype<GlProbeDual>(GlProbeDual)
                        catchAll<GlProbeDual>()
                    }
                }
            }

            val wire = "300d060355040306032b634d020107".hexToByteArray()
            val decoded = der.decodeFromByteArray<GlDualBase>(wire)
            der.encodeToByteArray(decoded).toHexString() shouldBe wire.toHexString()
        }
    }

    "CHOICE and nested dispatch" - {
        /*
         * choice_arm_tag_dispatch_unvalidated
         *
         * BUG: encodeChoiceSerializableValue never validates the leading tag of the element an
         * arm actually produced against the static CHOICE dispatch table (which exists only on
         * the decode side). An arm that supplies its own Asn1Encodable encoding can therefore
         * emit an element whose tag belongs to a DIFFERENT arm — the value silently comes back
         * as that other alternative.
         *
         * TRIGGER: Sneaky("x") encodes its own Asn1.Int(777) -> 02 02 03 09, which is IntArm's
         * dispatch slot; decoding returns IntArm(777). Controls: the two honest arms round-trip
         * byte-identically, proving the dispatch table itself is well-formed.
         */
        "choice_arm_tag_dispatch_unvalidated" {
            // Control (A): honest arms round-trip.
            val intArm: GlBar = GlBar.IntArm(5)
            DER.decodeFromByteArray<GlBar>(DER.encodeToByteArray(intArm)) shouldBe intArm
            val armTwo: GlBar = GlBar.ArmTwo("y")
            DER.decodeFromByteArray<GlBar>(DER.encodeToByteArray(armTwo)) shouldBe armTwo

            // Fault (B): the colliding arm is silently re-typed on decode (or must be rejected
            // at encode time — either is correct, silently swapping alternatives is not).
            val sneaky: GlBar = GlBar.Sneaky("x")
            DER.decodeFromByteArray<GlBar>(DER.encodeToByteArray(sneaky)) shouldBe sneaky
        }

        /*
         * inline_wrapped_choice_forcedchoice_mispredict
         *
         * BUG: possibleBaseLeadingTags does not reset `forcedChoice` when recursing through a
         * @JvmInline wrapper, so a CHOICE behind a value class is predicted as Exact({SEQUENCE})
         * instead of the union of its arm tags. The nullable presence inference then treats a
         * PRESENT choice value as absent: it nullifies the property and re-binds its element to
         * the next sibling.
         *
         * TRIGGER: H(boxed = Boxed(ArmI(9))) encodes to 30 03 02 01 09 and decodes back as
         * H(boxed = null, n = 9) — byte-identical, object-divergent. Control: the equivalent
         * direct-sealed model is correctly rejected as ambiguous.
         */
        "inline_wrapped_choice_forcedchoice_mispredict" {
            val value = GlH(GlBoxed(GlArmI(9)))
            shouldThrow<SerializationException> { DER.encodeToByteArray(value) }
        }

        /*
         * recursive_openpoly_child_decode_fail
         *
         * BUG: decodeCurrentElementWith decodes a nested open-polymorphic child in an isolated
         * one-element decoder but the enclosing structure decoder's elementIndex is not advanced
         * for the re-dispatched child. At nesting depth >= 2 the structure therefore still reports
         * one unconsumed element and decodeElementIndex raises
         * "Too many ASN.1 elements for <Subtype>: all 1 properties decoded, but 1 element(s) remain".
         *
         * TRIGGER: PImpl(PImpl(null)) -> a3 02 a3 00, produced by the library's own encoder, then
         * decoded back. Control: depth 1 (a3 00) decodes fine, and the failure is independent of
         * maxNestingDepth, so it is element accounting and not the depth guard.
         */
        "recursive_openpoly_child_decode_fail" {
            val der = DER {
                maxNestingDepth = 500
                serializersModule = SerializersModule {
                    polymorphicByTag(DsP::class, serialName = "DsP") { subtype<DsPImpl>() }
                }
            }

            // Control (A): depth 1 works.
            val depth1: DsP = DsPImpl(null)
            der.decodeFromByteArray<DsP>(der.encodeToByteArray(depth1)) shouldBe depth1

            // Fault (B): depth 2 — the library's own output — is refused.
            val depth2: DsP = DsPImpl(DsPImpl(null))
            val encoded = der.encodeToByteArray(depth2)
            encoded.toHexString() shouldBe "a302a300"
            der.decodeFromByteArray<DsP>(encoded) shouldBe depth2
        }

        /*
         * nullable_openpoly_silent_misbind_v3
         *
         * BUG: possibleBaseLeadingTags hard-codes Exact({SEQUENCE}) for OPEN-polymorphic
         * (polymorphicByTag) descriptors although the wire carries the BARE subtype encoding. A
         * present polymorphic element is therefore treated as an omission: the nullable property
         * decodes null without consuming its element, which then mis-binds into the following
         * property.
         *
         * TRIGGER: PolyShiftOpt(a = 1, p = OpenInt(7)) encoded with encodeDefaults = false comes
         * back as PolyShiftOpt(a = 1, p = null, q = 7) — byte-identical, semantically wrong.
         */
        "nullable_openpoly_silent_misbind_v3" {
            val der = DER {
                encodeDefaults = false
                serializersModule = SerializersModule {
                    polymorphicByTag(GlOpenBase::class, serialName = "GlOpenBase") {
                        subtype<GlOpenInt>()
                        subtype<GlOpenBool>()
                    }
                }
            }

            val value = GlPolyShiftOpt(a = 1, p = GlOpenInt(7))
            der.decodeFromByteArray<GlPolyShiftOpt>(der.encodeToByteArray(value)) shouldBe value
        }
    }
}
