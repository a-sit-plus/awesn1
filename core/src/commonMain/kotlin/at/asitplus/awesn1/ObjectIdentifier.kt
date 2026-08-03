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
import kotlin.concurrent.Volatile
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
    bytes: ByteArray?,
    nodes: List<VarUInt>?
) : Asn1Encodable<Asn1Primitive>, Comparable<ObjectIdentifier> {
    init {
        if ((bytes == null) == (nodes == null)) {
            //we're not even declaring this, since this is an implementation error on our end
            throw ImplementationError("either nodes or bytes required")
        }
        if (bytes?.isEmpty() == true || nodes?.isEmpty() == true)
            throw Asn1Exception("Empty OIDs are not supported")

        bytes?.validate() //as cheap as it gets: traverse once and fail early.
        nodes?.apply {
            if (size < 2) throw Asn1StructuralException("at least two nodes required!")
            if (first() > 2u) throw Asn1Exception("OID top-level arc can only be number 0, 1 or 2")
            if (first() < 2u) {
                if (get(1) > 39u) throw Asn1Exception("Second segment must be <40")
            }
        }
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

    // Sentinel-cached instead of `orLazy` delegates (no per-OID Lazy/closure objects — OIDs are numerous in real
    // input). For a parsed OID, `bytesCache` is set eagerly and `nodesCache` is decoded lazily from the bytes; for a
    // programmatic OID built from nodes, `bytesCache` is encoded lazily, so `nodesForBytes` retains the source nodes
    // only in that case. Benign idempotent race, same @Volatile posture as cachedContentLength/cachedHash.
    private val nodesForBytes: List<VarUInt>? = if (bytes == null) nodes else null
    @Volatile
    private var bytesCache: ByteArray? = bytes
    @Volatile
    private var nodesCache: List<String>? = null // not initialized eagerly; it might throw

    /**
     * Efficient, but cursed encoding of OID nodes, see [Microsoft's KB entry on OIDs](https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-object-identifier)
     * for details.
     * Lazily evaluated.
     */
    val bytes: ByteArray get() = bytesCache ?: nodesForBytes!!.toOidBytes().also { bytesCache = it }

    /**
     * Lazily evaluated list of OID nodes (e.g. `[1, 2, 35, 4654]`)
     */
    val nodes: List<String> get() {
        nodesCache?.let { return it }
        nodesForBytes?.let { nodes ->
            return nodes.map { it.toDecimalString(MAX_SUBIDENTIFIER_BYTES) }
                .also { nodesCache = it }
        }
        val firstSubidentifierEndExclusive = this.bytes.indexOfFirst { it >= 0 } + 1
        val (firstSubidentifier, firstTailIndex) =
            this.bytes.decodeAsn1VarBigUIntValue(0, firstSubidentifierEndExclusive)
        val (first, second) = firstSubidentifier.toOidRootArcs()
        var index = firstTailIndex
        val collected = mutableListOf(first, second)
        while (index < this.bytes.size) {
            if (this.bytes[index] >= 0) {
                collected += VarUInt(this.bytes[index].toUInt())
                index++
            } else {
                val nodeStart = index
                while (this.bytes[index] < 0) {
                    index++
                }
                val nodeEndExclusive = index + 1
                val (decoded, nextIndex) = this.bytes.decodeAsn1VarBigUIntValue(nodeStart, nodeEndExclusive)
                collected += decoded
                index = nextIndex
            }
        }
        return collected.map { it.toDecimalString(MAX_SUBIDENTIFIER_BYTES) }.also { nodesCache = it }
    }

    /**
     * Creates an OID in the 2.25 subtree that requires no formal registration.
     * E.g. the UUID `550e8400-e29b-41d4-a716-446655440000` results in the OID
     * `2.25.113059749145936325402354257176981405696`
     */
    @OptIn(ExperimentalUuidApi::class)
    constructor(uuid: Uuid) : this(
        bytes = null,
        nodes = listOf(VarUInt(2u), VarUInt(25u), VarUInt(uuid.toByteArray()))
    )

    /**
     * @param nodes OID Tree nodes passed in order (e.g. 1u, 2u, 96u, …)
     * @throws Asn1Exception if less than two nodes are supplied, the first node is >2 or the second node is >39
     */
    constructor(vararg nodes: UInt) : this(
        bytes = nodes.toOidBytes(),
        nodes = null
    )

    /**
     * @param oid OID string in human-readable format (e.g. "1.2.96" or "1 2 96")
     * @throws Asn1Exception on illegal input
     */
    @Throws(Asn1Exception::class)
    constructor(oid: String) : this(
        bytes = null,
        nodes =
            (oid.split(if (oid.contains('.')) '.' else ' '))
                .map { VarUInt.fromDecimalString(it, maxInputLength = MAX_SUBIDENTIFIER_CHARS) }
    )


    /**
     * @return human-readable format (e.g. "1.2.96")
     */
    override fun toString(): String {
        return nodes.joinToString(".")
    }

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
                return ObjectIdentifier(bytes = src.content, nodes = null)
            }
        },
        fallbackSerializer = ObjectIdentifierStringSerializer,
    ) {
        override val descriptor: SerialDescriptor =
            PrimitiveSerialDescriptor(ASN1_DESCRIPTOR_OBJECT_IDENTIFIER, PrimitiveKind.STRING)

        /** maximum characters per sub-identifier when decoding from string */
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
            ObjectIdentifier(bytes = bytes, nodes = null)

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
object ObjectIdentifierStringSerializer : KSerializer<ObjectIdentifier> {
    override val descriptor = PrimitiveSerialDescriptor(ASN1_DESCRIPTOR_OBJECT_IDENTIFIER, PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): ObjectIdentifier =
        ObjectIdentifier(decoder.decodeString())

    override fun serialize(encoder: Encoder, value: ObjectIdentifier) {
        encoder.encodeString(value.toString())
    }

}
