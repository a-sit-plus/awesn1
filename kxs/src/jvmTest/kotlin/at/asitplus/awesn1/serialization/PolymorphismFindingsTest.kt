// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(ExperimentalSerializationApi::class, ExperimentalStdlibApi::class)

package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Encodable
import at.asitplus.awesn1.Identifiable
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.readOid
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.jvm.JvmInline
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.SetSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.modules.SerializersModule


//hot take: make this a test-only helper shared across all test sources in all modules?
private inline fun <reified T> Der.roundTrip(value: T): T = decodeFromByteArray(encodeToByteArray(value))

private interface GlRequest

@Serializable
private data class GlApprovedRequest(val id: Int) : GlRequest

@Serializable
private data class GlRejectedRequest(val id: Int) : GlRequest

// Suite names preserve the original finding identifiers.
val bytag_declared_leadingtags_ignored_on_encode by matrixSuite {
    "Explicit leading tags determine the encoded discriminator and preserve the registered subtype." {
        val der = DER {
            serializersModule = SerializersModule {
                polymorphicByTag(GlRequest::class, serialName = "GlRequest") {
                    subtype<GlApprovedRequest>(Asn1Element.Tag.SET)
                    subtype<GlRejectedRequest>(Asn1Element.Tag.SEQUENCE)
                }
            }
        }

        val approved: GlRequest = GlApprovedRequest(42)
        der.roundTrip<GlRequest>(approved) shouldBe approved
    }
}

private interface GlTagB

@Serializable
@JvmInline
private value class GlTagBInt(val value: Int) : GlTagB

@Serializable
private data class GlTagBStr(val value: String) : GlTagB

@Serializable
private data class GlUntaggedPolyHolder(val poly: GlTagB)

@Serializable
private data class GlTaggedPolyHolder(@Asn1Tag(tagNumber = 1uL) val poly: GlTagB)

// Both tagged and untagged polymorphic properties round-trip with their subtype intact.
val bytag_poly_inherited_tag_undecodable by matrixSuite {
    val der = DER {
        serializersModule = SerializersModule {
            polymorphicByTag(GlTagB::class, serialName = "GlTagB") {
                subtype<GlTagBInt>()
                subtype<GlTagBStr>()
            }
        }
    }

    "An untagged polymorphic property round-trips." {
        val untagged = GlUntaggedPolyHolder(GlTagBInt(5))
        der.roundTrip<GlUntaggedPolyHolder>(untagged) shouldBe untagged
    }

    "A tagged polymorphic property also round-trips." {
        val tagged = GlTaggedPolyHolder(GlTagBInt(5))
        der.roundTrip<GlTaggedPolyHolder>(tagged) shouldBe tagged
    }
}

private interface GlShape

@Serializable
private data class GlCircle(val r: Int) : GlShape

@Serializable
private data class GlSquare(val side: Int) : GlShape

val bytag_registered_leadingtags_encode_ignored_silent_misbind by matrixSuite {
    "A serializer registered under an explicit leading tag round-trips through that dispatch entry." {
        val der = DER {
            serializersModule = SerializersModule {
                polymorphicByTag(GlShape::class, serialName = "GlShape") {
                    subtype(GlCircle.serializer(), setOf(Asn1Element.Tag.INT)) { it is GlCircle }
                    subtype<GlSquare>()
                }
            }
        }

        val circle: GlShape = GlCircle(3)
        der.roundTrip<GlShape>(circle) shouldBe circle
    }
}

private interface GlOpenBase2

@Serializable
private data class GlOpenStruct(val v: Int) : GlOpenBase2

@Serializable
@JvmInline
private value class GlOpenPrim(val v: Int) : GlOpenBase2

@Serializable
private data class GlOpenTaggedHolder(
    @Asn1Tag(tagNumber = 0uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC) val p: GlOpenBase2,
)

val openpoly_property_tag_replaces_discriminator by matrixSuite {
    "A tagged property preserves the structured subtype through a round-trip." {
        val der = DER {
            serializersModule = SerializersModule {
                polymorphicByTag(GlOpenBase2::class, serialName = "GlOpenBase2") {
                    subtype<GlOpenStruct>()
                    subtype<GlOpenPrim>()
                }
            }
        }

        val value = GlOpenTaggedHolder(GlOpenStruct(5))
        der.roundTrip<GlOpenTaggedHolder>(value) shouldBe value
    }
}

private interface DsOpenByTag

@Serializable
@JvmInline
private value class DsOpenInt(val value: Int) : DsOpenByTag

@Serializable
@Asn1Tag(tagNumber = 1uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC, constructed = Asn1Tag.ConstructedBit.PRIMITIVE)
@JvmInline
private value class DsOpenStr(val value: String) : DsOpenByTag

@Serializable
private data class DsOpenWrapper(
    @Asn1Tag(tagNumber = 0uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC, constructed = Asn1Tag.ConstructedBit.PRIMITIVE)
    val v: DsOpenByTag,
)

// Tagged primitive subtypes round-trip and retain distinct discriminator tags.
val openpoly_primitive_tag_asymmetry by matrixSuite {
    val der = DER {
        serializersModule = SerializersModule {
            polymorphicByTag(DsOpenByTag::class, serialName = "DsOpenByTag") {
                subtype<DsOpenInt>()
                subtype<DsOpenStr>()
            }
        }
    }

    "A bare primitive subtype round-trips." {
        val bare: DsOpenByTag = DsOpenInt(7)
        der.roundTrip<DsOpenByTag>(bare) shouldBe bare
    }

    "Wrapping the subtype in a tagged property preserves dispatch." {
        val wrapped = DsOpenWrapper(DsOpenInt(7))
        der.decodeFromDer<DsOpenWrapper>(der.encodeToByteArray(wrapped)) shouldBe wrapped
    }

    "The wrapper retains a distinct discriminator for each primitive subtype." {
        der.encodeToByteArray(DsOpenWrapper(DsOpenStr("hi")))[2] shouldNotBe
                der.encodeToByteArray(DsOpenWrapper(DsOpenInt(7)))[2]
    }
}

private interface DsPoly

@Serializable
@Asn1Tag(tagNumber = 3uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
private data class DsPolyA(val x: Int, val y: Int) : DsPoly

@Serializable
private data class DsEnvTag(
    @Asn1Tag(tagNumber = 7uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    val poly: DsPoly,
    val n: Int,
)

// Tag dispatch preserves the subtype of a property with an explicit tag.
val openpoly_tagdispatch_wrapper_tag by matrixSuite {
    val der = DER {
        serializersModule = SerializersModule {
            polymorphicByTag(DsPoly::class, serialName = "DsPoly") { subtype<DsPolyA>() }
        }
    }

    "An unwrapped structured subtype round-trips." {
        val bare: DsPoly = DsPolyA(1, 2)
        der.roundTrip<DsPoly>(bare) shouldBe bare
    }

    "The same subtype round-trips through an @Asn1Tag wrapper." {
        val wrapped = DsEnvTag(DsPolyA(1, 2), 99)
        der.decodeFromDer<DsEnvTag>(der.encodeToByteArray(wrapped)) shouldBe wrapped
    }
}

private interface GlPolyOidBase : Identifiable

@Serializable
private data class GlSubInt(val value: Int) : GlPolyOidBase, Identifiable by Companion {
    companion object : OidProvider<GlSubInt> {
        override val oid: ObjectIdentifier = ObjectIdentifier("1.2.3.1")
    }
}

@Serializable
private data class GlContainer(
    @Asn1Tag(tagNumber = 0uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    val ext: GlPolyOidBase,
    val metadata: GlMetadata,
)

@Serializable
private data class GlMetadata(val note: String)

// A polymorphic property tag does not affect the following metadata field.
val stale_inherited_openpoly_tag by matrixSuite {
    val der = DER {
        serializersModule = SerializersModule {
            polymorphicByOid(GlPolyOidBase::class, serialName = "GlPolyOidBase") {
                subtype<GlSubInt>(GlSubInt)
            }
        }
    }

    val value = GlContainer(GlSubInt(7), GlMetadata("hello"))
    val canonical = der.encodeToByteArray(value)

    "Canonical output decodes with the original metadata tag." {
        der.decodeFromByteArray<GlContainer>(canonical) shouldBe value
    }

    "Metadata retagged to match the preceding property is rejected." {
        val retagged = canonical.copyOf().also { bytes ->
            val idx = bytes.indexOfLast { it == 0x30.toByte() }
            bytes[idx] = 0xA0.toByte()
        }
        shouldThrow<SerializationException> { der.decodeFromByteArray<GlContainer>(retagged) }
    }
}

private interface GlVRoot : Identifiable

@Serializable
private open class GlVBase(val a: Int) : GlVRoot {
    override val oid: ObjectIdentifier get() = Companion.oid
    override fun equals(other: Any?) = other is GlVBase && a == other.a && this::class == other::class
    override fun hashCode() = a
    companion object : OidProvider<GlVBase> {
        override val oid: ObjectIdentifier = ObjectIdentifier("2.999.997.1")
    }
}

@Serializable
private class GlVSub(val b: Int) : GlVBase(1) {
    companion object : OidProvider<GlVSub> {
        override val oid: ObjectIdentifier = ObjectIdentifier("2.999.997.2")
    }
}

// OID dispatch preserves the runtime subclass and its additional fields.
val byoid_aliased_oid_silent_narrowing_v2 by matrixSuite {
    val der = DER {
        serializersModule = SerializersModule {
            polymorphicByOid(GlVRoot::class, serialName = "GlVRoot") {
                subtype<GlVBase>(GlVBase)
                subtype<GlVSub>(GlVSub)
            }
        }
    }

    "The base class selects its own registration." {
        val base: GlVRoot = GlVBase(1)
        der.roundTrip<GlVRoot>(base).shouldBeInstanceOf<GlVBase>()
    }

    "The subclass selects its own registration and retains field b." {
        val sub: GlVRoot = GlVSub(2)
        der.roundTrip<GlVRoot>(sub)
            .shouldBeInstanceOf<GlVSub>().b shouldBe 2
    }
}

private interface GlSelBase : Identifiable

@Serializable
private data class GlSubOidExact(val ref: ObjectIdentifier, val value: Int) : GlSelBase, Identifiable by Companion {
    companion object : OidProvider<GlSubOidExact> {
        override val oid: ObjectIdentifier =
            ObjectIdentifier("2.25.97297256932939567799793869759424299335")
    }
}

// A non-leading OID discriminator in a SEQUENCE is rejected.
val custom_oidselector_drop_misalignment by matrixSuite {
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
    "A SEQUENCE discriminator must be its first child." {
        shouldThrow<SerializationException> { der.decodeFromByteArray<GlSelBase>(wire) }
    }
}

private interface GlOidA : Identifiable

@Serializable(with = GlIdentifiableSet.Serializer::class)
private data class GlIdentifiableSet(val values: Set<Int>) : GlOidA, Identifiable by Companion {
    object Serializer : KSerializer<GlIdentifiableSet> {
        private val delegate = SetSerializer(Int.serializer())
        override val descriptor: SerialDescriptor get() = delegate.descriptor
        override fun serialize(encoder: Encoder, value: GlIdentifiableSet) = delegate.serialize(encoder, value.values)
        override fun deserialize(decoder: Decoder) = GlIdentifiableSet(delegate.deserialize(decoder))
    }

    companion object : OidProvider<GlIdentifiableSet> {
        override val oid: ObjectIdentifier = ObjectIdentifier("1.2.3.7")
    }
}

val oid_discriminator_displaced_by_set_sorting by matrixSuite {
    "SET sorting makes the OID discriminator ambiguous, so registration is rejected." {
        shouldThrow<IllegalArgumentException> {
            DER {
                serializersModule = SerializersModule {
                    polymorphicByOid(GlOidA::class, serialName = "GlOidA") {
                        subtype<GlIdentifiableSet>(GlIdentifiableSet)
                    }
                }
            }
        }
    }
}

private interface GlDualBase : Identifiable

@Serializable
private data class GlProbeDual(override val oid: ObjectIdentifier, val v: Int) : GlDualBase {
    companion object : OidProvider<GlProbeDual> {
        override val oid: ObjectIdentifier = ObjectIdentifier("2.5.4.3")
    }
}

val oid_dispatch_dual_registration_discriminator_swap by matrixSuite {
    "Exact and catch-all registration of the same class preserves the wire discriminator." {
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

@Serializable
private sealed interface GlBar {
    @Serializable
    @JvmInline
    value class IntArm(val n: Int) : GlBar

    @Serializable
    @Asn1Tag(tagNumber = 2uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    data class ArmTwo(val y: String) : GlBar

    @Serializable
    data class Sneaky(val s: String) : GlBar, Asn1Encodable<Asn1Element> {
        override fun encodeToTlv(): Asn1Element = Asn1.Int(777)
    }
}

// CHOICE dispatch preserves each arm, including an arm with a custom ASN.1 encoding.
val choice_arm_tag_dispatch_unvalidated by matrixSuite {
    "Ordinary CHOICE arms round-trip." {
        val intArm: GlBar = GlBar.IntArm(5)
        DER.roundTrip<GlBar>(intArm) shouldBe intArm
        val armTwo: GlBar = GlBar.ArmTwo("y")
        DER.roundTrip<GlBar>(armTwo) shouldBe armTwo
    }

    "A custom ASN.1 encoding also preserves the selected CHOICE arm." {
        val sneaky: GlBar = GlBar.Sneaky("x")
        DER.roundTrip<GlBar>(sneaky) shouldBe sneaky
    }
}

@Serializable
private sealed interface GlChoice2

@Serializable
@JvmInline
private value class GlArmI(val n: Int) : GlChoice2

@Serializable
private data class GlArmB(val s: String) : GlChoice2

@Serializable
@JvmInline
private value class GlBoxed(val v: GlChoice2)

@Serializable
private data class GlH(val boxed: GlBoxed? = null, val n: Int? = null)

val inline_wrapped_choice_forcedchoice_mispredict by matrixSuite {
    "An inline-wrapped CHOICE with ambiguous nullable sibling tags is rejected during encoding." {
        val value = GlH(GlBoxed(GlArmI(9)))
        shouldThrow<SerializationException> { DER.encodeToByteArray(value) }
    }
}

private interface DsP

@Serializable
@Asn1Tag(tagNumber = 3uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
private data class DsPImpl(val next: DsP? = null) : DsP

// Recursive open-polymorphic values round-trip at both one and two levels.
val recursive_openpoly_child_decode_fail by matrixSuite {
    val der = DER {
        maxNestingDepth = 500
        serializersModule = SerializersModule {
            polymorphicByTag(DsP::class, serialName = "DsP") { subtype<DsPImpl>() }
        }
    }

    "A single level round-trips." {
        val depth1: DsP = DsPImpl(null)
        der.roundTrip<DsP>(depth1) shouldBe depth1
    }

    "Nested dispatch consumes the child exactly once." {
        val depth2: DsP = DsPImpl(DsPImpl(null))
        val encoded = der.encodeToByteArray(depth2)
        encoded.toHexString() shouldBe "a302a300"
        der.decodeFromByteArray<DsP>(encoded) shouldBe depth2
    }
}

private interface GlOpenBase

@Serializable
@JvmInline
private value class GlOpenInt(val value: Int) : GlOpenBase

@Serializable
@Asn1Tag(tagNumber = 3uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC, constructed = Asn1Tag.ConstructedBit.PRIMITIVE)
@JvmInline
private value class GlOpenBool(val value: Boolean) : GlOpenBase

@Serializable
private data class GlPolyShiftOpt(val a: Int, val p: GlOpenBase?, val q: Int = 99)

val nullable_openpoly_silent_misbind_v3 by matrixSuite {
    "A present nullable open-polymorphic value remains bound to its own property." {
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
        der.roundTrip<GlPolyShiftOpt>(value) shouldBe value
    }
}
