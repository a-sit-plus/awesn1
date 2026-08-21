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
import kotlin.experimental.or
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * ASN.1 BIT STRING, enforcing strict DER rules:
 * 1. The number of padding bits must be in range 0..7
 * 2. The raw bytes must not be empty if padding bits are set
 * 3. The padding bits must be zero
 *
 * When serialized to a non-DER format, the following representation is used:`"$numPaddingBits:${base64Strict(bitCarryingBytes)}"`
 *
 * ```
 * val bitSet = BitSet.fromLogicalBitString("001")
 * val bitString = Asn1BitString(bitSet)
 *
 * Json.encodeToString(bitString)  //produces "5:IA=="
 * ```
 */
@ConsistentCopyVisibility
@Serializable(with = Asn1BitString.Companion::class)
data class Asn1BitString private constructor(

    val numPaddingBits: Byte,

    /**
     * DER-compatible MSB0 bytes. The returned array is the current backing array; mutability hardening is tracked
     * separately from the bit-vector refactor.
     */
    val bitCarryingBytes: ByteArray,

    ) : Asn1Encodable<Asn1Primitive>, Msb0BitVector by validatedBitVector(numPaddingBits, bitCarryingBytes) {

    /** Number of meaningful bits; DER padding is excluded. */
    override val logicalBitCount get() = bitCarryingBytes.size.toLong() * 8 - numPaddingBits

    /**
     * Helper constructor for logical-bit packing functions.
     */
    private constructor(derValue: Pair<Byte, ByteArray>) : this(derValue.first, derValue.second)

    /**
     * Creates an ASN.1 BIT STRING from the compact logical view of [source]. The conversion is immediate and independent
     * of later source mutations. Because [BitSet] is unbounded, unset bits after its highest set index are not encoded.
     */
    constructor(source: BitSet) : this(fromBits(source))

    /** Creates an ASN.1 BIT STRING containing every represented bit of fixed-size [source], including trailing zeroes. */
    constructor(source: BoundedBitVector) : this(fromBits(source))

    /** Creates a compact ASN.1 BIT STRING from the finite logical view of [source]. */
    constructor(source: UnboundedBitVector) : this(fromBits(source))

    /** Constructs an ASN.1 BIT STRING containing exactly the specified logical [bits]. */
    constructor(vararg bits: Boolean) : this(fromBits(bits.asIterable()))

    /**
     * Constructs a byte-aligned ASN.1 BIT STRING using [source] as its MSB0 backing bytes without copying.
     *
     * @throws Asn1Exception if [source] does not fulfill ASN.1 BIT STRING requirements
     */
    constructor(source: ByteArray) : this(Pair(0x00.toByte(), source))

    /**
     * Creates an independent [BitSet] containing the same set logical indexes. As [BitSet] is unbounded, this conversion
     * intentionally loses trailing unset bits and the exact [logicalBitCount].
     */
    fun toBitSet(): BitSet {
        val bitset = BitSet(logicalBitCount)
        for (index in 0 until logicalBitCount) if (get(index)) bitset.set(index)
        return bitset
    }


    companion object : Asn1Serializer<Asn1Primitive, Asn1BitString>(
        leadingTags = setOf(Asn1Element.Tag.BIT_STRING),
        decodable = object : Asn1Decodable<Asn1Primitive, Asn1BitString> {
            @Throws(Asn1Exception::class)
            override fun doDecode(src: Asn1Primitive): Asn1BitString {
                if (src.contentLength == 0) throw Asn1Exception("Empty ASN.1 BIT STRING found")
                return Asn1BitString(src.content[0], src.content.sliceArray(1..<src.content.size))
            }
        },
        fallbackSerializer = Asn1BitStringComponentSerializer,
    ) {
        override val descriptor: SerialDescriptor =
            PrimitiveSerialDescriptor(ASN1_DESCRIPTOR_BIT_STRING, PrimitiveKind.STRING)

        private fun fromBits(bits: Iterable<Boolean>): Pair<Byte, ByteArray> {
            val bytes = mutableListOf<Byte>()
            var logicalBitCount = 0L
            for (bit in bits) {
                if (logicalBitCount % 8 == 0L) bytes.add(0)
                if (bit) bytes[bytes.lastIndex] = bytes.last() or BitVector.getMsb0Mask(logicalBitCount)
                logicalBitCount++
            }
            val paddingBits = ((8 - logicalBitCount % 8) % 8).toByte()
            return paddingBits to bytes.toByteArray()
        }

        /**
         * @throws Asn1Exception if the ASN.1 BIT STRING requirements are not fulfilled
         * */
        @InternalAwesn1Api
        fun fromRawParts(numPaddingBits: Byte, rawBytes: ByteArray): Asn1BitString =
            Asn1BitString(numPaddingBits, rawBytes)

        private fun validatedBitVector(numPaddingBits: Byte, bytes: ByteArray): Msb0BitArray = runRethrowing {
            require(numPaddingBits in 0..7) { "Number of padding bits must be in range 0..7. Found: $numPaddingBits" }
            if (numPaddingBits > 0) require(bytes.isNotEmpty()) { "Raw bytes must not be empty if padding bits are set" }
            repeat(numPaddingBits.toInt()) { bit ->
                require((bytes.last().toInt() and (1 shl bit)) == 0) {
                    "Last $numPaddingBits padding bits must be zeroed out. Last byte is: ${
                        bytes.last().toUByte().toString(2).padStart(8, '0')
                    }"
                }
            }
            Msb0BitArray(bytes, bytes.size.toLong() * 8 - numPaddingBits)
        }
    }

    override fun encodeToTlv() =
        Asn1Primitive(Asn1Element.Tag.BIT_STRING, byteArrayOf(numPaddingBits, *bitCarryingBytes))

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Asn1BitString

        if (numPaddingBits != other.numPaddingBits) return false
        if (!bitCarryingBytes.contentEquals(other.bitCarryingBytes)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = numPaddingBits.toInt()
        result = 31 * result + bitCarryingBytes.contentHashCode()
        return result
    }

    override fun toString(): String {
        return "Asn1BitString(" +
                "numPaddingBits=$numPaddingBits, " +
                "rawBytes=${bitCarryingBytes.contentToString()}" +
                ")"
    }
}

/**
 * String serializer for [Asn1BitString] used for interoperability with non-DER serialization formats.
 *
 * When [Asn1BitString] is used with the `awesn1.kxs` DER format, this serializer is bypassed and native BIT STRING DER TLV
 * encoding/decoding is used.
 */
@OptIn(ExperimentalEncodingApi::class)
private object Asn1BitStringComponentSerializer : KSerializer<Asn1BitString> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor(ASN1_DESCRIPTOR_BIT_STRING, PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: Asn1BitString) {
        val encodedRaw = Base64.encode(value.bitCarryingBytes)
        encoder.encodeString("${value.numPaddingBits}:$encodedRaw")
    }

    override fun deserialize(decoder: Decoder): Asn1BitString {
        val serialized = decoder.decodeString()
        val parts = serialized.split(':', limit = 2)
        require(parts.size == 2) { "Invalid Asn1BitString format: '$serialized'" }
        val padding = parts[0].toInt()
        val raw = Base64.decode(parts[1])
        return Asn1BitString.fromRawParts(padding.toByte(), raw)
    }
}
