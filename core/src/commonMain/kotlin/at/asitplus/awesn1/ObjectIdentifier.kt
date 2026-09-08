// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(InternalAwesn1Api::class, ExperimentalUnsignedTypes::class)

package at.asitplus.awesn1

import at.asitplus.awesn1.VarUInt.Companion.decodeAsn1VarBigUIntValue
import at.asitplus.awesn1.VarUInt.Companion.writeAsn1VarInt
import at.asitplus.awesn1.encoding.decode
import at.asitplus.awesn1.encoding.internal.Sink
import at.asitplus.awesn1.encoding.internal.writeAsn1VarInt
import at.asitplus.awesn1.serialization.Asn1Serializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * ASN.1 OBJECT IDENTIFIER featuring the most cursed encoding of numbers known to man, which probably surfaced due to an ungodly combination
 * of madness, cruelty and a twisted sense of humour. Courtesy of what were most probably tormented souls to begin with.
 *
 * @param nodes OID Tree nodes passed in order (e.g. 1u, 2u, 96u, …)
 * @throws Asn1Exception if less than two nodes are supplied, the first node is >2 or the second node is >39
 */
@Serializable(with = ObjectIdentifier.Companion::class)
class ObjectIdentifier @Throws(Asn1Exception::class) private constructor(
    /**
     * The sole storage: DER content bytes, i.e. base-128 subidentifiers. Everything else — [nodes], [toString],
     * [equals], [hashCode], [compareTo], [encodeToTlv] — is derived from these, so this class holds no other state
     * and no caches: it is fully immutable and safe to share across threads and to use as a map key.
     *
     * Base-128 is also the most compact representation available: a subidentifier costs `ceil(bits / 7)` bytes, and
     * measured across the ~2750 registered OIDs 85.8 % of subidentifiers fit in a single byte. Keeping decoded nodes
     * instead costs ~44 bytes each, which is what this class used to do.
     *
     * **The array is never handed out.** [bytes] copies, because a write into it would corrupt every derived value
     * at once. The private constructor adopts, so the internal paths that encode a fresh array — the [String],
     * [Uuid] and vararg constructors — do not copy it again.
     */
    private val contentBytes: ByteArray
) : Asn1Encodable<Asn1Primitive>, Comparable<ObjectIdentifier> {
    init {
        if (contentBytes.isEmpty()) throw Asn1Exception("Empty OIDs are not supported")
        contentBytes.validate() //as cheap as it gets: traverse once and fail early.
    }

    private fun ByteArray.validate() {
        // OID content is a sequence of base-128 subidentifiers, including the first byte(s), which encode
        // the first two arcs as one value: (arc0 * 40) + arc1. Any valid first subidentifier maps back to
        // a sane root: 0..39 -> 0.x, 40..79 -> 1.x, 80+ -> 2.x. For example, content 0x81 0x00 is valid
        // and decodes to first subidentifier 128, i.e. OID 2.48. So there is intentionally no eager
        // single-byte top-level-arc check here; structural base-128 validation is enough.
        var i = 0
        while (i < size) {
            if (this[i].toInt() and 0x80 == 0) {
                i++
                continue
            }

            if (this[i].toInt() and 0x7f == 0) {
                throw Asn1Exception("OID node is not minimally encoded")
            }

            while (i < size && this[i] < 0) i++
            if (i == size) throw Asn1Exception("Encoded OID does not end with a valid ASN.1 varint")
            i++
        }
    }

    /**
     * Efficient, but cursed encoding of OID nodes, see [Microsoft's KB entry on OIDs](https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-object-identifier)
     * for details.
     *
     * Returns a **copy**: these bytes are this OID's only state, so handing out the live array would let a caller
     * corrupt its identity, ordering and encoding. Use [nodeCount] if you only need the arity, since that reads the
     * storage without copying it.
     */
    val bytes: ByteArray get() = contentBytes.copyOf()

    /**
     * Number of nodes (arcs) in this OID, without materialising them.
     *
     * Every subidentifier ends on a byte with the high bit clear, and the first one encodes two arcs, so this is a
     * single allocation-free pass over the content bytes — cheaper than `nodes.size`, which renders every node to a
     * [String] first.
     */
    val nodeCount: Int get() = contentBytes.count { it >= 0 } + 1

    /**
     * List of OID nodes in order (e.g. `["1", "2", "35", "4654"]`), decoded on demand.
     *
     * Not cached: nothing but the content bytes is retained (see [contentBytes]). Repeated access re-decodes, so
     * hold the result if you need it more than once.
     *
     * @throws Asn1Exception if a subidentifier's magnitude exceeds [MAX_SUBIDENTIFIER_BYTES]
     */
    val nodes: List<String>
        get() = ArrayList<String>(nodeCount).also { out ->
            forEachNode(onSmall = { out += it.toString() }, onBig = { out += it.toDecimalString(MAX_SUBIDENTIFIER_BYTES) })
        }

    /**
     * Walks the subidentifiers in order, handing each node to [onSmall] when it fits a [Long] and to [onBig]
     * otherwise. The first subidentifier carries two arcs, so it produces two invocations.
     *
     * Fused deliberately: decoding a node used to cost a boundary scan, a second scan inside the varint decoder, a
     * third walk building a `UByteArray`, a boxed [VarUInt], and a base-10^9 decimal conversion — to render a number
     * that is below 128 for 85.8 % of subidentifiers. [onSmall] takes the value rather than a rendered [String] so
     * that [toString] can append digits straight into its builder without an intermediate allocation per node.
     */
    private inline fun forEachNode(onSmall: (Long) -> Unit, onBig: (VarUInt) -> Unit) {
        var index = 0
        while (index < contentBytes.size) {
            // `validate` guarantees every run terminates within bounds; the check keeps this safe regardless,
            // which matters on Kotlin/Wasm, where an out-of-bounds read traps instead of throwing.
            var end = index
            var accumulator = 0L
            while (end < contentBytes.size && contentBytes[end] < 0) {
                accumulator = (accumulator shl 7) or (contentBytes[end].toLong() and 0x7f)
                end++
            }
            accumulator = (accumulator shl 7) or (contentBytes[end].toLong() and 0x7f)
            val length = end - index + 1

            // a run of up to 8 base-128 bytes carries at most 56 bits, so the accumulator above is exact
            val fitsLong = length <= 8
            if (index == 0) {
                // the first subidentifier encodes both root arcs as (arc0 * 40) + arc1
                if (fitsLong) when {
                    accumulator < 40 -> { onSmall(0); onSmall(accumulator) }
                    accumulator < 80 -> { onSmall(1); onSmall(accumulator - 40) }
                    else -> { onSmall(2); onSmall(accumulator - 80) }
                } else {
                    val (first, second) = decodeSubidentifier(index, end + 1).toOidRootArcs()
                    onBig(first)
                    onBig(second)
                }
            } else {
                if (fitsLong) onSmall(accumulator) else onBig(decodeSubidentifier(index, end + 1))
            }
            index = end + 1
        }
    }

    /** Decodes the subidentifier in `[from, toExclusive)` as a [VarUInt]; only for runs too long for a [Long]. */
    private fun decodeSubidentifier(from: Int, toExclusive: Int): VarUInt =
        contentBytes.decodeAsn1VarBigUIntValue(from, toExclusive).first

    /**
     * Creates an OID in the 2.25 subtree that requires no formal registration.
     * E.g. the UUID `550e8400-e29b-41d4-a716-446655440000` results in the OID
     * `2.25.113059749145936325402354257176981405696`
     */
    @OptIn(ExperimentalUuidApi::class)
    constructor(uuid: Uuid) : this(
        listOf(VarUInt(2u), VarUInt(25u), VarUInt(uuid.toByteArray())).toOidBytes()
    )

    /**
     * @param nodes OID Tree nodes passed in order (e.g. 1u, 2u, 96u, …)
     * @throws Asn1Exception if less than two nodes are supplied, the first node is >2 or the second node is >39
     */
    constructor(vararg nodes: UInt) : this(nodes.toOidBytes())

    /**
     * @param oid OID string in human-readable format (e.g. "1.2.96" or "1 2 96")
     * @throws Asn1Exception on illegal input
     */
    @Throws(Asn1Exception::class)
    constructor(oid: String) : this(
        (oid.split(if (oid.contains('.')) '.' else ' '))
            .map { VarUInt.fromDecimalString(it, maxInputLength = MAX_SUBIDENTIFIER_CHARS) }
            .toOidBytes()
    )


    /**
     * @return human-readable format (e.g. "1.2.96")
     *
     * Recomputed on every call, since only the content bytes are retained. The library's own OID rendering
     * ([Asn1Primitive.prettyPrint]) decodes a throwaway [ObjectIdentifier] per element anyway, so an instance-level
     * cache could never be hit there; hold the result yourself if you render the same OID repeatedly.
     */
    override fun toString(): String = StringBuilder(nodeCount * 3).apply {
        var first = true
        forEachNode(
            onSmall = { if (first) first = false else append('.'); append(it) },
            onBig = { if (first) first = false else append('.'); append(it.toDecimalString(MAX_SUBIDENTIFIER_BYTES)) },
        )
    }.toString()

    override fun equals(other: Any?): Boolean {
        if (other == null) return false
        if (other !is ObjectIdentifier) return false
        return bytes contentEquals other.bytes
    }

    override fun hashCode(): Int {
        return bytes.contentHashCode()
    }

    /**
     * Orders OIDs by their DER encoding ([bytes]) using unsigned lexicographic byte comparison — i.e. the
     * canonical "sorted by encoding" order (e.g. RFC 4514 §2.3 multi-valued RDN ordering). Consistent with
     * [equals]: `compareTo(other) == 0` iff `equals(other)`.
     */
    override fun compareTo(other: ObjectIdentifier): Int {
        val a = bytes
        val b = other.bytes
        val n = minOf(a.size, b.size)
        for (i in 0 until n) {
            val c = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
            if (c != 0) return c
        }
        return a.size - b.size
    }

    /**
     * @return an OBJECT IDENTIFIER [Asn1Primitive]
     */
    override fun encodeToTlv() = Asn1Primitive(Asn1Element.Tag.OID, bytes)

    companion object : Asn1Serializer<Asn1Primitive, ObjectIdentifier>(
        leadingTags = setOf(Asn1Element.Tag.OID),
        decodable = object : Asn1Decodable<Asn1Primitive, ObjectIdentifier> {
            override fun doDecode(src: Asn1Primitive): ObjectIdentifier {
                if (src.contentLength < 1) throw Asn1StructuralException("Empty OIDs are not supported")
                // copies for the same reason decodeFromAsn1ContentBytes does: `src.content` is the element's live
                // array. Calls the constructor rather than that factory because the companion is not initialised
                // yet at this point — this object is an argument to its own supertype constructor.
                return ObjectIdentifier(src.content.copyOf())
            }
        },
        fallbackSerializer = ObjectIdentifierStringSerializer,
    ) {
        override val descriptor: SerialDescriptor =
            PrimitiveSerialDescriptor(ASN1_DESCRIPTOR_OBJECT_IDENTIFIER, PrimitiveKind.STRING)

        /** maximum characters per sub-identifier when decoding from string */
        /**
         * Maximum size (characters) of a dotted OID string accepted by [ObjectIdentifierStringSerializer].
         * [MAX_SUBIDENTIFIER_CHARS] bounds a single node, but nothing bounds how many nodes a string declares, and
         * each one is retained. 4 KiB admits ~2000 nodes, which is orders of magnitude past any registered OID.
         */
        const val MAX_OID_STRING_CHARS = 4 * 1024

        const val MAX_SUBIDENTIFIER_CHARS = 150
        /** maximum bytes per sub-identifier when encoding to string */
        const val MAX_SUBIDENTIFIER_BYTES = 64

        /**
         * Parses an OBJECT IDENTIFIER contained in [src] to an [ObjectIdentifier]
         * @throws Asn1Exception  all sorts of errors on invalid input
         */
        /**
         * Casts out the evil demons that haunt OID components encoded into ASN.1 content [bytes].
         * If you want to parse human-readable OID representations, just use the ObjectIdentifier constructor!
         * @return ObjectIdentifier if decoding succeeded
         * @throws Asn1Exception all sorts of errors on invalid input
         */
        @Throws(Asn1Exception::class)
        fun decodeFromAsn1ContentBytes(bytes: ByteArray): ObjectIdentifier =
            // copies: [bytes] belongs to the caller (on the parse path it is the element's live content array), and
            // it becomes this OID's only state, so sharing it would let a later write corrupt the OID's identity
            ObjectIdentifier(bytes.copyOf())

        @OptIn(InternalAwesn1Api::class)
        private inline fun encodeOidBytes(writeRootNodes: (Sink) -> Unit, writeTailNodes: (Sink) -> Unit): ByteArray =
            throughBuffer { sink ->
                writeRootNodes(sink)
                writeTailNodes(sink)
            }

        //only called on the slow path, when not parsed from bytes
        @OptIn(InternalAwesn1Api::class)
        private fun UIntArray.toOidBytes(): ByteArray {
            if (size < 2) throw Asn1StructuralException("at least two nodes required!")
            if (first() > 2u) throw Asn1Exception("OID top-level arc can only be number 0, 1 or 2")
            if (first() < 2u && get(1) > 39u) throw Asn1Exception("Second segment must be <40")

            return encodeOidBytes({ sink ->
                if (first() < 2u) {
                    sink.writeAsn1VarInt(first() * 40u + get(1))
                } else {
                    sink.writeAsn1VarInt(VarUInt(get(1)) + 80u)
                }
            }) { sink ->
                for (i in 2 until size) {
                    sink.writeAsn1VarInt(this[i])
                }
            }
        }

        //only called on the slow path
        @OptIn(InternalAwesn1Api::class)
        private fun List<VarUInt>.toOidBytes(): ByteArray {
            // these used to live in `init`, guarding the node-carrying construction path; encoding is now eager, so
            // they guard it here instead, before anything is written
            if (isEmpty()) throw Asn1Exception("Empty OIDs are not supported")
            if (size < 2) throw Asn1StructuralException("at least two nodes required!")
            if (first() > 2u) throw Asn1Exception("OID top-level arc can only be number 0, 1 or 2")
            if (first() < 2u && get(1) > 39u) throw Asn1Exception("Second segment must be <40")

            return encodeOidBytes({ sink ->
                sink.writeAsn1VarInt(
                    if (first() < 2u) VarUInt((first().shortValue() * 40 + get(1).shortValue()).toUInt())
                    else get(1) + 80u
                )
            }) { sink ->
                for (i in 2 until size) {
                    sink.writeAsn1VarInt(this[i])
                }
            }
        }

    }
}

//uses schoolbook subtraction, but is only called on the slow path, when not parsing from bytes
private fun VarUInt.toOidRootArcs(): Pair<VarUInt, VarUInt> =
    when {
        this < 40u -> VarUInt(0u) to this
        this < 80u -> VarUInt(1u) to this - 40u
        else -> VarUInt(2u) to this - 80u
    }

/**
 * Adds [oid] to the implementing class
 */
interface Identifiable {
    val oid: ObjectIdentifier
}

/**
 * decodes this [Asn1Primitive]'s content into an [ObjectIdentifier]
 *
 * @throws Asn1Exception on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.readOid() = runRethrowing {
    decode(Asn1Element.Tag.OID) { ObjectIdentifier.decodeFromAsn1ContentBytes(it) }
}

/**
 * String-based serializer for [ObjectIdentifier].
 *
 * The serialized representation is the dotted-decimal OID string (for example `1.2.840.113549`).
 * When used with the `awesn1.kxs` DER format, this fallback representation is bypassed and native OBJECT IDENTIFIER
 * DER TLV encoding/decoding is used.
 */
object ObjectIdentifierStringSerializer : BoundedFallbackSerializer<ObjectIdentifier> {
    override val descriptor = PrimitiveSerialDescriptor(ASN1_DESCRIPTOR_OBJECT_IDENTIFIER, PrimitiveKind.STRING)

    /**
     * maximum size (characters) for decoding. Defaults to [MAX_OID_STRING_CHARS], far tighter than the shared
     * [BoundedFallbackSerializer.defaultDecodingLimit]: every node becomes a retained `VarUInt`, so a dotted string
     * of nothing but `.1` costs ~224x its own size in transient allocation and ~22x retained.
     */
    override var decodingLimit: Int = ObjectIdentifier.MAX_OID_STRING_CHARS

    override fun decodeBounded(encoded: String): ObjectIdentifier = ObjectIdentifier(encoded)

    override fun encodeBounded(value: ObjectIdentifier): String = value.toString()

}
