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
    bytes: ByteArray?,
    nodes: List<VarUInt>?
) :
    Asn1Encodable<Asn1Primitive> {
    init {
        if ((bytes == null) && (nodes == null)) {
            //we're not even declaring this, since this is an implementation error on our end
            throw IllegalArgumentException("either nodes or bytes required")
        }
        if (bytes?.isEmpty() == true || nodes?.isEmpty() == true)
            throw Asn1Exception("Empty OIDs are not supported")

        bytes?.apply {
            if (first().toUByte() > 127u) throw Asn1Exception("OID top-level arc can only be number 0, 1 or 2")
            //this is the best we can do
            if (last() < 0) throw Asn1Exception("Encoded OID does not end with a valid ASN.1 varint")
        }
        nodes?.apply {
            if (size < 2) throw Asn1StructuralException("at least two nodes required!")
            if (first() > 2u) throw Asn1Exception("OID top-level arc can only be number 0, 1 or 2")
            if (first() < 2u) {
                if (get(1) > 39u) throw Asn1Exception("Second segment must be <40")
            } else {
                if (get(1) > 47u) throw Asn1Exception("Second segment must be <48")
            }
        }
    }


    /**
     * Efficient, but cursed encoding of OID nodes, see [Microsoft's KB entry on OIDs](https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-object-identifier)
     * for details.
     * Lazily evaluated.
     */
    val bytes: ByteArray by if (bytes != null) lazyOf(bytes) else lazy {
        nodes!!.toOidBytes()
    }

    /**
     * Lazily evaluated list of OID nodes (e.g. `[1, 2, 35, 4654]`)
     */
    val nodes: List<String> by lazy {
        if (nodes != null) nodes.map { it.toString() } else {
            val (first, second) =
                if (this.bytes[0] >= 80) {
                    VarUInt(2u) to VarUInt(this.bytes[0].toUByte() - 80u)
                } else {
                    VarUInt(this.bytes[0].toUByte() / 40u) to VarUInt(this.bytes[0].toUByte() % 40u)
                }
            var index = 1
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
            collected.map { it.toString() }
        }
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
        nodes = (oid.split(if (oid.contains('.')) '.' else ' ')).map { VarUInt(it) }
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
        private inline fun encodeOidBytes(firstByte: Byte, writeTailNodes: (Sink) -> Unit): ByteArray =
            throughBuffer { sink ->
                sink.writeByte(firstByte)
                writeTailNodes(sink)
            }

        @OptIn(InternalAwesn1Api::class)
        private fun UIntArray.toOidBytes(): ByteArray {
            return encodeOidBytes((first() * 40u + get(1)).toUByte().toByte()) { sink ->
                for (i in 2 until size) {
                    sink.writeAsn1VarInt(this[i])
                }
            }
        }

        @OptIn(InternalAwesn1Api::class)
        private fun List<VarUInt>.toOidBytes(): ByteArray {
            return encodeOidBytes((first().shortValue() * 40 + get(1).shortValue()).toUByte().toByte()) { sink ->
                for (i in 2 until size) {
                    sink.writeAsn1VarInt(this[i])
                }
            }
        }

    }
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
