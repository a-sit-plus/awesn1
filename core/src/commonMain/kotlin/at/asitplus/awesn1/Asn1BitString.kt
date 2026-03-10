// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(InternalAwesn1Api::class)

package at.asitplus.awesn1

import at.asitplus.awesn1.serialization.Asn1Serializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * ASN.1 BIT STRING
 */
@Serializable(with = Asn1BitString.Companion::class)
class Asn1BitString private constructor(
    /**
     * Number of bits needed to pad the bit string to a byte boundary
     */
    val numPaddingBits: Byte,

    /**
     * The raw bytes containing the bit string. The bits contained in [rawBytes] are laid out, as printed when calling
     * [BitSet.toBitStringView], right-padded with [numPaddingBits] many zero bits to the last byte boundary.
     *
     * The overall [Asn1Primitive.content] resulting from [encodeToTlv] is `byteArrayOf(numPaddingBits, *rawBytes)`
     */
    val rawBytes: ByteArray,

    ) : Asn1Encodable<Asn1Primitive> {


    /**
     * helper constructor to be able to use [fromBitSet]
     */
    private constructor(derValue: Pair<Byte, ByteArray>) : this(derValue.first, derValue.second)

    /**
     * Creates an ASN.1 BIT STRING from the provided bitSet.
     * The transformation to [rawBytes] and the calculation of [numPaddingBits] happens
     * immediately in the constructor. Hence, modifications to the source BitSet have no effect on the resulting [Asn1BitString].
     *
     * **BEWARE:** a bitset (as [BitSet] implements it) is, by definition, only as long as the highest bit set!
     * Hence, trailing zeroes are **ALWAYS** stripped. If you require tailing zeroes, the easiest quick-and-dirty hack to accomplish this in general is as follows:
     *
     *  - set the last bit you require as tailing zero to one
     *  - call this constructor
     *  - flip the previously set bit back (this will be the lowest bit set in last byte of [rawBytes]).
     *
     * @param source the source [BitSet], which is discarded after [rawBytes] and [numPaddingBits] have been calculated
     */
    constructor(source: BitSet) : this(fromBitSet(source))

    /**
     * Constructs an ASN.1 BIT STRING with [source] used for [rawBytes] and zero padding bits
     */
    constructor(source: ByteArray) : this(Pair(0x00.toByte(), source))

    /**
     * Transforms [rawBytes] and wraps into a [BitSet]. The last [numPaddingBits] bits are ignored.
     * This is a deep copy and mirrors the bits in every byte to match
     * the native bitset layout where bit any byte indices run in opposite direction.
     * Hence, modifications to the resulting bitset do not affect [rawBytes]
     *
     * Note: Tailing zeroes never count towards the length of the bitset
     *
     * See [BitSet] for more details on bit string representation vs memory layout.
     *
     */
    fun toBitSet(): BitSet {
        val size = rawBytes.size.toLong() * 8 - numPaddingBits
        val bitset = BitSet(size)
        for (i in rawBytes.indices) {
            val bitOffset = i.toLong() * 8L
            for (bitIndex in 0..<8) {
                val globalIndex = bitOffset + bitIndex
                if (globalIndex == size) return bitset
                bitset[globalIndex] = (rawBytes[i].toInt() and (0x80 shr bitIndex) != 0)
            }
        }
        return bitset
    }

    companion object : Asn1Serializer<Asn1Primitive, Asn1BitString>(
        leadingTags = setOf(Asn1Element.Tag.BIT_STRING),
        decodable = object : Asn1Decodable<Asn1Primitive, Asn1BitString> {
            @Throws(Asn1Exception::class)
            override fun doDecode(src: Asn1Primitive): Asn1BitString {
                if (src.contentLength == 0) return Asn1BitString(0, byteArrayOf())
                if (src.content.first() > 7) throw Asn1Exception("Number of padding bits < 7")
                return Asn1BitString(src.content[0], src.content.sliceArray(1..<src.content.size))
            }
        },
        fallbackSerializer = Asn1BitStringSerializer,
    ) {
        override val descriptor: SerialDescriptor =
            PrimitiveSerialDescriptor(ASN1_DESCRIPTOR_BIT_STRING, PrimitiveKind.STRING)

        private fun fromBitSet(bitSet: BitSet): Pair<Byte, ByteArray> {
            val rawBytes = bitSet.bytes.map {
                var res = 0
                for (i in 0..7) {
                    if (it.toUByte().toInt() and (0x80 shr i) != 0) res = res or (0x01 shl i)
                }
                res.toUByte().toByte()
            }.toByteArray()
            return ((8 - (bitSet.length() % 8)) % 8).toByte() to rawBytes
        }

        internal fun fromRawParts(numPaddingBits: Byte, rawBytes: ByteArray): Asn1BitString =
            Asn1BitString(numPaddingBits, rawBytes)

    }

    override fun encodeToTlv() = Asn1Primitive(Asn1Element.Tag.BIT_STRING, byteArrayOf(numPaddingBits, *rawBytes))
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Asn1BitString

        if (numPaddingBits != other.numPaddingBits) return false
        if (!rawBytes.contentEquals(other.rawBytes)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = numPaddingBits.toInt()
        result = 31 * result + rawBytes.contentHashCode()
        return result
    }
}

/**
 * String serializer for [Asn1BitString] used for interoperability with non-DER serialization formats.
 *
 * When used with the `awesn1.kxs` DER format, this serializer is bypassed and native BIT STRING DER TLV
 * encoding/decoding is used.
 */
@OptIn(ExperimentalEncodingApi::class)
internal object Asn1BitStringSerializer : KSerializer<Asn1BitString> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor(ASN1_DESCRIPTOR_BIT_STRING, PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: Asn1BitString) {
        val encodedRaw = Base64.encode(value.rawBytes)
        encoder.encodeString("${value.numPaddingBits}:$encodedRaw")
    }

    override fun deserialize(decoder: Decoder): Asn1BitString {
        val serialized = decoder.decodeString()
        val parts = serialized.split(':', limit = 2)
        require(parts.size == 2) { "Invalid Asn1BitString format: '$serialized'" }
        val padding = parts[0].toInt().also { require(it in 0..7) { "Invalid padding bits: $it" } }
        val raw = Base64.decode(parts[1])
        return Asn1BitString.fromRawParts(padding.toByte(), raw)
    }
}
