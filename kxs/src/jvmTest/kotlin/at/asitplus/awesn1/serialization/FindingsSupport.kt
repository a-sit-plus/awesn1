// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(ExperimentalSerializationApi::class, ExperimentalStdlibApi::class)

/*
 * Shared fixtures for the serialization findings suites (`*FindingsTest.kt` in this package).
 *
 * The models are the @Serializable shapes the findings need; the helpers are the measurement and probe
 * utilities they share. They live here rather than in one suite so that a finding can be filed under the
 * domain it belongs to without dragging its fixtures along.
 */

package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Encodable
import at.asitplus.awesn1.Asn1OctetString
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.Identifiable
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.append
import kotlin.jvm.JvmInline
import kotlinx.serialization.Contextual
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.SetSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.serializer

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/** Runs [block] on a thread with an explicitly small stack and returns whatever escaped it. */
internal fun onThreadWithStack(stackSize: Long, block: () -> Unit): Throwable? {
    var escaped: Throwable? = null
    val thread = Thread(null, {
        try {
            block()
        } catch (t: Throwable) {
            escaped = t
        }
    }, "awesn1-small-stack", stackSize)
    thread.start()
    thread.join()
    return escaped
}

/** DER length octets (short form below 0x80, long form above). */
internal fun derLength(length: Int): ByteArray {
    if (length < 0x80) return byteArrayOf(length.toByte())
    var remaining = length
    val octets = mutableListOf<Byte>()
    while (remaining > 0) {
        octets.add(0, (remaining and 0xFF).toByte())
        remaining = remaining ushr 8
    }
    return byteArrayOf((0x80 or octets.size).toByte()) + octets.toByteArray()
}

/** `levels` nested, otherwise empty SEQUENCEs — the classic depth bomb, ~3-5 bytes per level. */
internal fun nestedSequenceDer(levels: Int): ByteArray {
    var body = ByteArray(0)
    repeat(levels) { body = byteArrayOf(0x30) + derLength(body.size) + body }
    return body
}

internal fun withClue(clue: String, block: () -> Unit) =
    try {
        block()
    } catch (t: AssertionError) {
        throw AssertionError("${t.message}\n--- probe output ---\n$clue", t)
    }

internal fun buildRecursiveGraph(depth: Int): DsPlainRecursive {
    var node = DsPlainRecursive(null)
    repeat(depth - 1) { node = DsPlainRecursive(node) }
    return node
}

// ---------------------------------------------------------------------------
// models
// ---------------------------------------------------------------------------

/** Plain structural recursion — goes through beginStructure, i.e. the guarded path. */
@Serializable
data class DsPlainRecursive(val child: DsPlainRecursive? = null)

/**
 * Recursion through an Asn1Serializable companion — the path DerDecoder routes to
 * decodeConcreteValue, which calls DerDepthGuard.ensureElementTreeFits().
 */
@Serializable(with = DsSerializableRecursive.Companion::class)
class DsSerializableRecursive(val child: DsSerializableRecursive?) : Asn1Encodable<Asn1Sequence> {
    override fun encodeToTlv(): Asn1Sequence = Asn1.Sequence { child?.let { +it.encodeToTlv() } }

    companion object : at.asitplus.awesn1.serialization.Asn1Serializable<Asn1Sequence, DsSerializableRecursive> {
        override val leadingTags: Set<Asn1Element.Tag> = setOf(Asn1Element.Tag.SEQUENCE)
        override fun doDecode(src: Asn1Sequence): DsSerializableRecursive =
            DsSerializableRecursive(
                if (src.children.isEmpty()) null
                else decodeFromTlv(src.children.first() as Asn1Sequence)
            )
    }
}

@Serializable
data class DsWrappedOctet(val payload: ByteArray) {
    override fun equals(other: Any?) = other is DsWrappedOctet && payload.contentEquals(other.payload)
    override fun hashCode() = payload.contentHashCode()
}

@Serializable
data class DsRawTagPlain(
    @Asn1Tag(tagNumber = 0uL, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    val e: Asn1Element,
)

@Serializable
data class DsRawTagContextual(
    @Asn1Tag(tagNumber = 0uL, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    @Contextual
    val e: Asn1Element,
)

@Serializable
data class DsInner(val x: Int)

@Serializable
data class DsConstTaggedNullable(
    @Asn1Tag(tagNumber = 0uL, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    val inner: DsInner?,
)

@Serializable
data class DsItemModel(
    @Asn1Tag(tagNumber = 1uL) val items: List<Int>?,
    @Asn1Tag(tagNumber = 2uL) val trail: Int,
)

interface DsOpenByTag

@Serializable
@JvmInline
value class DsOpenInt(val value: Int) : DsOpenByTag

@Serializable
@Asn1Tag(tagNumber = 1uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC, constructed = Asn1Tag.ConstructedBit.PRIMITIVE)
@JvmInline
value class DsOpenStr(val value: String) : DsOpenByTag

@Serializable
data class DsOpenWrapper(
    @Asn1Tag(tagNumber = 0uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC, constructed = Asn1Tag.ConstructedBit.PRIMITIVE)
    val v: DsOpenByTag,
)

interface DsPoly

@Serializable
@Asn1Tag(tagNumber = 3uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
data class DsPolyA(val x: Int, val y: Int) : DsPoly

@Serializable
data class DsEnvTag(
    @Asn1Tag(tagNumber = 7uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    val poly: DsPoly,
    val n: Int,
)

interface DsP

@Serializable
@Asn1Tag(tagNumber = 3uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
data class DsPImpl(val next: DsP? = null) : DsP

// ---------------------------------------------------------------------------
// models
// ---------------------------------------------------------------------------

@Serializable
data class GlOctetStringHolder(val os: Asn1OctetString)

@Serializable
data class GlByteArrayHolder(val os: ByteArray) {
    override fun equals(other: Any?) = other is GlByteArrayHolder && os.contentEquals(other.os)
    override fun hashCode() = os.contentHashCode()
}

@Serializable
data class GlInferClass(
    @Asn1Tag(tagNumber = 5uL, tagClass = Asn1Tag.Class.INFER) val a: String? = null,
    @Asn1Tag(tagNumber = 5uL) val b: Int? = null,
)

@Serializable
data class GlBothContext(
    @Asn1Tag(tagNumber = 5uL) val a: String? = null,
    @Asn1Tag(tagNumber = 5uL) val b: Int? = null,
)

interface GlVRoot : Identifiable

@Serializable
open class GlVBase(val a: Int) : GlVRoot {
    override val oid: ObjectIdentifier get() = Companion.oid
    override fun equals(other: Any?) = other is GlVBase && a == other.a && this::class == other::class
    override fun hashCode() = a
    companion object : OidProvider<GlVBase> {
        override val oid: ObjectIdentifier = ObjectIdentifier("2.999.997.1")
    }
}

@Serializable
class GlVSub(val b: Int) : GlVBase(1) {
    companion object : OidProvider<GlVSub> {
        override val oid: ObjectIdentifier = ObjectIdentifier("2.999.997.2")
    }
}

interface GlRequest

@Serializable
data class GlApprovedRequest(val id: Int) : GlRequest

@Serializable
data class GlRejectedRequest(val id: Int) : GlRequest

interface GlTagB

@Serializable
@JvmInline
value class GlTagBInt(val value: Int) : GlTagB

@Serializable
data class GlTagBStr(val value: String) : GlTagB

@Serializable
data class GlUntaggedPolyHolder(val poly: GlTagB)

@Serializable
data class GlTaggedPolyHolder(@Asn1Tag(tagNumber = 1uL) val poly: GlTagB)

interface GlShape

@Serializable
data class GlCircle(val r: Int) : GlShape

@Serializable
data class GlSquare(val side: Int) : GlShape

@Serializable
data class GlOctetConstructed(
    @Asn1Tag(tagNumber = 1uL, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED) val b: ByteArray,
) {
    override fun equals(other: Any?) = other is GlOctetConstructed && b.contentEquals(other.b)
    override fun hashCode() = b.contentHashCode()
}

@Serializable
data class GlOctetPrimitive(
    @Asn1Tag(tagNumber = 1uL, constructed = Asn1Tag.ConstructedBit.PRIMITIVE) val b: ByteArray,
) {
    override fun equals(other: Any?) = other is GlOctetPrimitive && b.contentEquals(other.b)
    override fun hashCode() = b.contentHashCode()
}

@Serializable
sealed interface GlBar {
    @Serializable
    @JvmInline
    value class IntArm(val n: Int) : GlBar

    @Serializable
    @Asn1Tag(tagNumber = 2uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    data class ArmTwo(val y: String) : GlBar

    @Serializable
    data class Sneaky(val s: String) : GlBar, at.asitplus.awesn1.Asn1Encodable<Asn1Element> {
        override fun encodeToTlv(): Asn1Element = Asn1.Int(777)
    }
}

@Serializable
data class GlConstructedTaggedBytes(
    @Asn1Tag(tagNumber = 0uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    val bytes: ByteArray,
) {
    override fun equals(other: Any?) = other is GlConstructedTaggedBytes && bytes.contentEquals(other.bytes)
    override fun hashCode() = bytes.contentHashCode()
}

@Serializable
data class GlConstructedTaggedInt(
    @Asn1Tag(tagNumber = 0uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    val n: Int,
)

interface GlSelBase : Identifiable

@Serializable
data class GlSubOidExact(val ref: ObjectIdentifier, val value: Int) : GlSelBase, Identifiable by Companion {
    companion object : OidProvider<GlSubOidExact> {
        override val oid: ObjectIdentifier =
            ObjectIdentifier("2.25.97297256932939567799793869759424299335")
    }
}

@Serializable
data class GlStringHolder(val s: String)

@Serializable
@JvmInline
value class GlUIntWrap(val v: UInt)

@Serializable
data class GlWithUIntWrap(val w: GlUIntWrap)

@Serializable
data class GlWithUInt(val w: UInt)

enum class GlMode { OFF, ON }

@Serializable
@JvmInline
value class GlPlainEnumHolder(val e: GlMode)

@Serializable
@Asn1Tag(tagNumber = 7uL, tagClass = Asn1Tag.Class.APPLICATION)
@JvmInline
value class GlTaggedEnumHolder(val e: GlMode)

@Serializable
data class GlPlainHolderHost(val a: GlPlainEnumHolder, val b: Int)

@Serializable
data class GlTaggedHolderHost(val a: GlTaggedEnumHolder, val b: Int)

@Serializable
data class GlConstructedEnumHost(
    @Asn1Tag(tagNumber = 2uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    val m: GlMode,
)

@Serializable
data class GlInner(val a: Int)

@Serializable
data class GlModelDefaultedOpt(
    val first: GlInner,
    val opt: GlInner = GlInner(7),
    @Asn1Tag(tagNumber = 1uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    val last: GlInner?,
)

@Serializable
data class GlModelNullableOpt(
    val first: GlInner,
    val opt: GlInner? = null,
    @Asn1Tag(tagNumber = 1uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    val last: GlInner?,
)

@Serializable
@JvmInline
value class GlToken(val value: Int)

object GlTokenSerializer : KSerializer<GlToken> {
    override val descriptor: SerialDescriptor =
        GlToken.serializer().descriptor.withAsn1LeadingTags(setOf(Asn1Element.Tag.STRING_UTF8))

    override fun serialize(encoder: Encoder, value: GlToken) = encoder.encodeString(value.value.toString())
    override fun deserialize(decoder: Decoder): GlToken = GlToken(decoder.decodeString().toInt())
}

@Serializable
data class GlP4(
    @Serializable(with = GlTokenSerializer::class) val t: GlToken? = null,
    val note: String = "",
)

@Serializable
@JvmInline
value class GlWrappedInt(val v: Int)

@Serializable
data class GlWrappedIntHolder(@Asn1Tag(tagNumber = 5uL) val x: GlWrappedInt?)

@Serializable
sealed interface GlChoice2

@Serializable
@JvmInline
value class GlArmI(val n: Int) : GlChoice2

@Serializable
data class GlArmB(val s: String) : GlChoice2

@Serializable
@JvmInline
value class GlBoxed(val v: GlChoice2)

@Serializable
data class GlH(val boxed: GlBoxed? = null, val n: Int? = null)

@Serializable
@SerialName("GlShared")
data class GlDisambiguated(
    @Asn1Tag(tagNumber = 0uL) val opt: Int? = null,
    @Asn1Tag(tagNumber = 1uL) val req: Int? = null,
)

@Serializable
@SerialName("GlShared")
data class GlAmbiguous(val opt: Int? = null, val req: Int? = null)

@Serializable
data class GlRootBoth(val a: GlDisambiguated, val b: GlAmbiguous)

@Serializable
data class GlPlainRecursive(val child: GlPlainRecursive? = null)

@Serializable
data class GlJustEnum(val e: GlMode? = null)

interface GlOpenBase

@Serializable
@JvmInline
value class GlOpenInt(val value: Int) : GlOpenBase

@Serializable
@Asn1Tag(tagNumber = 3uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC, constructed = Asn1Tag.ConstructedBit.PRIMITIVE)
@JvmInline
value class GlOpenBool(val value: Boolean) : GlOpenBase

@Serializable
data class GlPolyShiftOpt(val a: Int, val p: GlOpenBase?, val q: Int = 99)

@Serializable
data class GlRawNullableHolder(val raw: Asn1Element? = null)

@Serializable
data class GlListNullSentinel(
    @Asn1Tag(tagNumber = 0uL, constructed = Asn1Tag.ConstructedBit.PRIMITIVE) val a: List<Int>?,
    val b: Int,
)

@Serializable
data class GlPrimitiveNullSentinel(
    @Asn1Tag(tagNumber = 0uL, constructed = Asn1Tag.ConstructedBit.PRIMITIVE) val a: String?,
    val b: Int,
)

@Serializable
data class GlHostNullableInt(val wrapped: OctetStringEncapsulated<Int?>)

@Serializable
data class GlHostRetaggedInfer(
    @Asn1Tag(tagNumber = 0uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC)
    val wrapped: OctetStringEncapsulated<Int>,
)

@Serializable
data class GlHostRetaggedConstructed(
    @Asn1Tag(tagNumber = 0uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    val wrapped: OctetStringEncapsulated<Int>,
)

interface GlOidA : Identifiable

@Serializable(with = GlIdentifiableSet.Serializer::class)
data class GlIdentifiableSet(val values: Set<Int>) : GlOidA, Identifiable by Companion {
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

interface GlDualBase : Identifiable

@Serializable
data class GlProbeDual(override val oid: ObjectIdentifier, val v: Int) : GlDualBase {
    companion object : OidProvider<GlProbeDual> {
        override val oid: ObjectIdentifier = ObjectIdentifier("2.5.4.3")
    }
}

interface GlOpenBase2

@Serializable
data class GlOpenStruct(val v: Int) : GlOpenBase2

@Serializable
@JvmInline
value class GlOpenPrim(val v: Int) : GlOpenBase2

@Serializable
data class GlOpenTaggedHolder(
    @Asn1Tag(tagNumber = 0uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC) val p: GlOpenBase2,
)

@Serializable
data class GlPrimTaggedHolder(
    @Asn1Tag(tagNumber = 0uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC, constructed = Asn1Tag.ConstructedBit.PRIMITIVE)
    val x: GlInner,
)

@Serializable
data class GlConsTaggedHolder(
    @Asn1Tag(tagNumber = 0uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    val x: GlInner,
)

@Serializable
data class GlTailLenient(val id: Int, val exts: LenientSet<Int>? = null)

@Serializable
data class GlTailNonNull(val id: Int, val exts: LenientSet<Int>)

interface GlPolyOidBase : Identifiable

@Serializable
data class GlSubInt(val value: Int) : GlPolyOidBase, Identifiable by Companion {
    companion object : OidProvider<GlSubInt> {
        override val oid: ObjectIdentifier = ObjectIdentifier("1.2.3.1")
    }
}

@Serializable
data class GlMetadata(val note: String)

@Serializable
data class GlContainer(
    @Asn1Tag(tagNumber = 0uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    val ext: GlPolyOidBase,
    val metadata: GlMetadata,
)
