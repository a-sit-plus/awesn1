// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(InternalAwesn1Api::class)

package at.asitplus.awesn1

import at.asitplus.awesn1.serialization.Asn1Serializable
import at.asitplus.awesn1.serialization.Asn1Serializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlin.experimental.and
import kotlin.experimental.inv
import kotlin.experimental.or
import kotlin.io.encoding.Base64

private fun lastByteMask(numPaddingBits: Int) = when (numPaddingBits) {
    1 -> 0xfe.toByte()
    2 -> 0xfc.toByte()
    3 -> 0xf8.toByte()
    4 -> 0xf0.toByte()
    5 -> 0xe0.toByte()
    6 -> 0xc0.toByte()
    7 -> 0x80.toByte()
    else -> 0xff.toByte()
}

private fun Byte.reverseBits(): Byte {
    var x = toInt()
    x = ((x ushr 1) and 0x55) or ((x and 0x55) shl 1)
    x = ((x ushr 2) and 0x33) or ((x and 0x33) shl 2)
    return ((x ushr 4) or (x shl 4)).toByte()
}

/** ASN.1 BIT STRING. When serialized to a non-DER format, uses: `base64Strict(content octets)`.
 * Different encoding rules apply for general bit strings ([Asn1BitString]), and named bit lists ([Asn1NamedBitList]). */
@Serializable(with=Asn1AbstractBitString.Companion::class)
sealed class Asn1AbstractBitString(
    /** the encoded raw bytes (lenient, if decoded from DER); number of padding bits followed by raw bytes */
    protected val rawBytes: ByteArray,
) : Asn1Encodable<Asn1Primitive> {
    init {
        if (rawBytes.isEmpty()) throw Asn1Exception("Empty ASN.1 BIT STRING found")
    }

    protected val rawNumPaddingBits get() = rawBytes[0].toInt() and 7

    // assumes that bitIndex was already bounds checked! it must be in [0, rawBytes.size*8 - paddingBits) */
    protected fun getBit(bitIndex: Long) =
        (rawBytes[1 + (bitIndex / 8).toInt()] and (0x80 shr (bitIndex and 7L).toInt()).toByte()) != 0.toByte()

    /** A copy of the bytes containing the BitString. Within each byte, bit 0 is the most significant.
     * This is normalized to comply with the type's canonical encoding (per DER), regardless of what the wire bytes were. */
    abstract val bitCarryingBytes: ByteArray
    /** The number of trailing meaningless zero padding bits at the end of [bitCarryingBytes]. Always in `0..7`. */
    abstract val numPaddingBits: Int

    /** Retrieves a single bit from the BIT STRING. Bits are addressed as per ASN.1, with index 0 being the most significant bit. */
    abstract operator fun get(bitIndex: Long): Boolean

    protected class Serializer<T: Asn1AbstractBitString>(ctor: (ByteArray)->T) : Asn1Serializer<Asn1Primitive, T>(
        leadingTags = setOf(Asn1Element.Tag.BIT_STRING),
        decodable = object : Asn1Decodable<Asn1Primitive, T> {
            @Throws(Asn1Exception::class)
            override fun doDecode(src: Asn1Primitive): T = ctor(src.content)
        },
        fallbackSerializer = object : StringFallbackSerializer<T> {
            override val descriptor: SerialDescriptor =
                PrimitiveSerialDescriptor(ASN1_DESCRIPTOR_BIT_STRING, PrimitiveKind.STRING)
            override fun encodeFallback(value: T): String =
                Base64.encode(value.rawBytes)
            override fun decodeFallback(encoded: String): T =
                ctor(Base64.decode(encoded))
        },
    ) {
        override val descriptor: SerialDescriptor =
            PrimitiveSerialDescriptor(ASN1_DESCRIPTOR_BIT_STRING, PrimitiveKind.STRING)
    }

    override fun encodeToTlv() = Asn1Primitive(Asn1Element.Tag.BIT_STRING, rawBytes)

    companion object : Asn1Serializable<Asn1Primitive, Asn1AbstractBitString> by Serializer({ Asn1BitString.adoptingTLVContentBytes(it) })
}

/** A general [Asn1AbstractBitString]. It has a concrete size ([sizeBits]/[sizeBytes]), and can be indexed accordingly. */
@Serializable(with = Asn1BitString.Companion::class)
class Asn1BitString private constructor(rawBytes: ByteArray) : Asn1AbstractBitString(rawBytes) {
    override val numPaddingBits: Int = if (rawBytes.size == 1) 0 else rawNumPaddingBits
    /** The size of the BIT STRING in bytes. */
    val sizeBytes: Int = rawBytes.size-1
    /** The size of the BIT STRING in bits. */
    val sizeBits: Long get() = sizeBytes * 8L - numPaddingBits
    /** The available indices into the BIT STRING. */
    val indices get() = (0 until sizeBits)

    override fun get(bitIndex: Long): Boolean {
        if (bitIndex !in indices) throw IndexOutOfBoundsException("Index $bitIndex out of bounds [0, $sizeBits)")
        return getBit(bitIndex)
    }
    override val bitCarryingBytes: ByteArray get() {
        if (rawBytes.size == 1) return byteArrayOf()
        val copy = rawBytes.copyOfRange(1, rawBytes.size)
        copy[copy.lastIndex] = copy[copy.lastIndex] and lastByteMask(numPaddingBits)
        return copy
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Asn1BitString) return false
        if (numPaddingBits != other.numPaddingBits) return false
        if (rawBytes.size != other.rawBytes.size) return false
        val mask = lastByteMask(numPaddingBits)
        return (1 until rawBytes.size).all {
            if (it == rawBytes.lastIndex) (rawBytes[it] and mask) == (other.rawBytes[it] and mask)
            else (rawBytes[it] == other.rawBytes[it])
        }
    }

    override fun hashCode() =
        rawBytes.foldIndexed(0) { idx, acc, next ->
            31 * acc + when (idx) {
                0 -> numPaddingBits.toByte()
                rawBytes.lastIndex -> (next and lastByteMask(numPaddingBits))
                else -> next
            }
        }

    companion object : Asn1Serializable<Asn1Primitive, Asn1BitString> by Serializer(::Asn1BitString) {
        /** Constructs a generalized ASN.1 BIT STRING from its logical byte content.
         * The string's length is `bytes.size / 8 - numPaddingBits`. [bytes] is copied.
         * If [numPaddingBits] is specified, the trailing bits must already be zeroed out in [bytes]. */
        operator fun invoke(bytes: ByteArray, numPaddingBits: Int = 0): Asn1BitString {
            if (numPaddingBits !in 0..7) throw Asn1Exception("Invalid numPaddingBits = $numPaddingBits")
            if (numPaddingBits != 0) {
                if (bytes.isEmpty()) throw Asn1Exception("Cannot have padding bits with empty data")
                if ((bytes.last() and lastByteMask(numPaddingBits).inv()) != 0.toByte()) throw Asn1Exception("Padding bits must be zeroed out")
            }
            return Asn1BitString(ByteArray(bytes.size+1) { if (it == 0) numPaddingBits.toByte() else bytes[it - 1] })
        }
        /** Constructs a generalized ASN.1 BIT STRING containing the specified bytes. */
        operator fun invoke(vararg bits: Boolean): Asn1BitString {
            if (bits.isEmpty()) return Asn1BitString(byteArrayOf(0x00))
            val paddingBits = 7-((bits.size-1)%8)
            val numBytes = (bits.size-1)/8 + 1
            val data = ByteArray(1+numBytes)
            data[0] = paddingBits.toByte()
            bits.forEachIndexed { i, state ->
                if (!state) return@forEachIndexed
                val byteIndex = 1+(i/8)
                data[byteIndex] = data[byteIndex] or (0x80 shr i%8).toByte()
            }
            return Asn1BitString(data)
        }
        @Deprecated("Since BitSet trims trailing zeroes, this actually constructs an Asn1NamedBitList", replaceWith = ReplaceWith("Asn1NamedBitList"))
        operator fun invoke(bits: BitSet) = Asn1NamedBitList(bits)
        @InternalAwesn1Api
        internal fun adoptingTLVContentBytes(bytes: ByteArray) = Asn1BitString(bytes)
    }
}

/** A ASN.1 BIT STRING containing a named bit list. It has unbounded logical size; all unencoded bits are assumed to be false. */
@Serializable(with = Asn1NamedBitList.Companion::class)
class Asn1NamedBitList private constructor(rawBytes: ByteArray) : Asn1AbstractBitString(rawBytes) {
    /** The highest index that has a `true` value, or `-1` if no values are `true` */
    val highestSetIndex: Long get() = neededBytes * 8L - numPaddingBits - 1
    /** The number of bytes that are needed to express the `true` bits */
    private val neededBytes: Int
    override val numPaddingBits: Int
    init {
        var _neededBytes: Int = 0
        var _numPaddingBits: Int = 0
        for (i in rawBytes.lastIndex downTo 1) {
            val byte = when (i) {
                rawBytes.lastIndex -> rawBytes[i] and lastByteMask(rawNumPaddingBits)
                else -> rawBytes[i]
            }
            if (byte == 0.toByte()) continue
            _neededBytes = i
            _numPaddingBits = byte.countTrailingZeroBits()
            break
        }
        // this construction is needed because the compiler is dumb
        neededBytes = _neededBytes
        numPaddingBits = _numPaddingBits
    }
    override val bitCarryingBytes: ByteArray get() {
        if (neededBytes == 0) return byteArrayOf()
        val copy = rawBytes.copyOfRange(1, neededBytes+1)
        copy[copy.lastIndex] = copy[copy.lastIndex] and lastByteMask(numPaddingBits)
        return copy
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Asn1NamedBitList) return false
        if (numPaddingBits != other.numPaddingBits) return false
        if (neededBytes != other.neededBytes) return false
        if (neededBytes == 0) return true
        val mask = lastByteMask(numPaddingBits)
        return (
            ((1 until neededBytes).all { rawBytes[it] == other.rawBytes[it] }) &&
            (rawBytes[neededBytes] and mask) == (other.rawBytes[neededBytes] and mask)
        )
    }

    override fun hashCode() =
        (1..neededBytes).fold(numPaddingBits.hashCode()) { acc, idx ->
            31 * acc + when (idx) {
                rawBytes.lastIndex -> (rawBytes[idx] and lastByteMask(numPaddingBits))
                else -> rawBytes[idx]
            }
        }

    override fun get(bitIndex: Long): Boolean {
        if (bitIndex < 0) throw IndexOutOfBoundsException("Index $bitIndex is out of bounds [0,+∞)")
        if (bitIndex > highestSetIndex) return false
        return getBit(bitIndex)
    }

    fun toBitSet() = BitSet.fromBytes(neededBytes) {
        when (val idx = it+1) {
            rawBytes.lastIndex -> (rawBytes[idx] and lastByteMask(numPaddingBits))
            else -> rawBytes[idx]
        }.reverseBits()
    }

    companion object : Asn1Serializable<Asn1Primitive, Asn1NamedBitList> by Serializer(::Asn1NamedBitList) {
        /** Constructs a named bit set with the bits contained in [bits] set to true. */
        operator fun invoke(bits: BitSet): Asn1NamedBitList {
            if (bits.isEmpty()) return Asn1NamedBitList(byteArrayOf(0x00))
            val bytes = bits.bytes
            return Asn1NamedBitList(ByteArray(bytes.size+1) { i ->
                if (i == 0) bytes.last().countLeadingZeroBits().toByte()
                else bytes[i-1].reverseBits()
            })
        }
        /** Constructs a named bit set containing the specified bits. Trailing bits are ignored, as per specification. */
        operator fun invoke(vararg bits: Boolean) = invoke(BitSet(*bits))
    }
}