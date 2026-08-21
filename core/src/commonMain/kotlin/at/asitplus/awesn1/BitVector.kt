// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1

import kotlin.experimental.and

/**
 * Logical, index-addressable bits without a size or byte-layout contract.
 *
 * Implementations define their valid index domain through [BoundedBitVector] or [UnboundedBitVector]. Byte packing is
 * deliberately absent: concrete types expose their own explicitly named LSB0 and MSB0 representations.
 *
 * This base interface deliberately does not extend [Iterable]. Iteration requires an end, but a plain bit vector has no
 * extent contract: [BoundedBitVector] must iterate exactly its [BoundedBitVector.logicalBitCount], including trailing
 * `false` positions, whereas [UnboundedBitVector] exposes only the finite prefix ending at [highestSetIndex]. Putting
 * either rule here would discard meaningful trailing `false` bits for some implementations or invent a finite end for
 * an unbounded abstraction. The extent-specific subinterfaces therefore define their own `Iterable<Boolean>` semantics.
 */
interface BitVector {
    /**
     * Returns the bit at [index]. Negative indexes always throw. A bounded implementation also throws when [index] is
     * not smaller than its size; every nonnegative index is valid for an unbounded implementation.
     */
    @Throws(IndexOutOfBoundsException::class)
    operator fun get(index: Long): Boolean

    /** Returns the first set bit at or after [fromIndex], or `-1` if no such bit exists. */
    @Throws(IndexOutOfBoundsException::class)
    fun nextSetBit(fromIndex: Long): Long

    /** Returns the first set bit after [index], or `-1` if no such bit exists. */
    @Throws(IndexOutOfBoundsException::class)
    fun nextSetBitAfter(index: Long): Long =
        if (index == Long.MAX_VALUE) -1 else nextSetBit(index + 1)

    /** Returns the greatest index whose bit is set, or `-1` if no bit is set. */
    fun highestSetIndex(): Long

    companion object {
        /** Returns the backing-byte index containing logical [index]. */
        @Throws(IndexOutOfBoundsException::class)
        internal fun getByteIndex(index: Long): Int {
            if (index < 0) throw IndexOutOfBoundsException("index = $index")
            val byteIndex = index / 8
            if (byteIndex > Int.MAX_VALUE) throw IndexOutOfBoundsException("byte index = $byteIndex")
            return byteIndex.toInt()
        }

        /** Returns the mask for logical [index] when bit zero is the least-significant bit of its byte. */
        internal fun getLsb0Mask(index: Long): Byte = (1 shl (index % 8).toInt()).toByte()

        /** Returns the mask for logical [index] when bit zero is the most-significant bit of its byte. */
        internal fun getMsb0Mask(index: Long): Byte = (0x80 ushr (index % 8).toInt()).toByte()

        /** Returns the minimum number of bytes required to store [logicalBitCount] bits. */
        internal fun getByteCount(logicalBitCount: Long): Int {
            if (logicalBitCount < 0) {
                throw IllegalArgumentException("a bit vector of size $logicalBitCount makes no sense")
            }
            val byteCount = logicalBitCount / 8 + if (logicalBitCount % 8 == 0L) 0 else 1
            // ponytail: JVM/native arrays cannot practically represent Int.MAX_VALUE elements.
            if (byteCount >= Int.MAX_VALUE) throw Asn1Exception("BitVector byte count exceeds supported range: $byteCount")
            return byteCount.toNonnegativeIntChecked("BitVector byte count")
        }

    }

    /** Orientation of logical bit indexes within each backing-array byte. Byte order itself is unchanged. */
    enum class BitOrder { LSB0, MSB0 }
}


/** A bit vector with an array representation whose native intra-byte orientation is [bitOrder]. */
interface ArrayBackedBitVector : BoundedBitVector {
    val bitOrder: BitVector.BitOrder
}

/** An array-backed vector whose logical index zero uses the most-significant bit of its first byte. */
interface Msb0BitVector : ArrayBackedBitVector {
    override val bitOrder: BitVector.BitOrder get() = BitVector.BitOrder.MSB0
}

/** An array-backed vector whose logical index zero uses the least-significant bit of its first byte. */
interface Lsb0BitVector : ArrayBackedBitVector {
    override val bitOrder: BitVector.BitOrder get() = BitVector.BitOrder.LSB0
}

/** A vector whose valid logical indexes are exactly `0..<logicalBitCount`. */
interface BoundedBitVector : BitVector, Iterable<Boolean> {
    /**
     * Exact number of addressable logical bit positions.
     *
     * Every index in `0..<logicalBitCount` belongs to this vector, including positions whose value is `false` and
     * trailing `false` positions after [BitVector.highestSetIndex]. This is not backing-array capacity: padding or other
     * physically stored bits outside this range are not part of the vector and cannot be addressed through [get].
     * For example, a value of `3` means that only indexes `0`, `1`, and `2` exist; index `3` is out of bounds even when
     * an array-backed implementation uses a whole byte internally.
     */
    val logicalBitCount: Long

    /** Iterates exactly [logicalBitCount] bits, including unset bits at either end. */
    override fun iterator(): Iterator<Boolean> = bitIterator(logicalBitCount)

    /** Returns exactly [logicalBitCount] logical bits in increasing index order. */
    fun toLogicalBitString(): String = joinToString("") { if (it) "1" else "0" }

    /** Returns the bytes needed for exactly [logicalBitCount] bits in LSB0 order; unused final-byte bits are zero. */
    fun toLsb0ByteArray(): ByteArray

    /** Returns the bytes needed for exactly [logicalBitCount] bits in MSB0 order; unused final-byte bits are zero. */
    fun toMsb0ByteArray(): ByteArray

    /** Iterates the exact bounded representation in LSB0 order; unused final-byte bits are zero. */
    fun lsb0ByteIterator(): ByteIterator

    /** Iterates the exact bounded representation in MSB0 order; unused final-byte bits are zero. */
    fun msb0ByteIterator(): ByteIterator
}

/**
 * A vector without a fixed logical upper bound. Every unset nonnegative index reads as `false`; mutation may still fail
 * when an index exceeds the concrete storage implementation. Iteration ends immediately after
 * [BitVector.highestSetIndex], and an empty vector therefore produces no elements.
 */
interface UnboundedBitVector : BitVector, Iterable<Boolean> {
    override fun iterator(): Iterator<Boolean> = bitIterator(highestSetIndex() + 1)

    /** Returns logical bits from index zero through [BitVector.highestSetIndex]. */
    fun toLogicalBitString(): String = joinToString("") { if (it) "1" else "0" }

    /** Returns the compact LSB0 representation ending at [BitVector.highestSetIndex]. */
    fun toLsb0ByteArray(): ByteArray

    /** Returns the compact MSB0 representation ending at [BitVector.highestSetIndex]. */
    fun toMsb0ByteArray(): ByteArray

    /** Iterates the compact LSB0 representation ending at [BitVector.highestSetIndex]. */
    fun lsb0ByteIterator(): ByteIterator

    /** Iterates the compact MSB0 representation ending at [BitVector.highestSetIndex]. */
    fun msb0ByteIterator(): ByteIterator
}

/** Mutation capability shared by bounded and unbounded bit vectors. */
interface MutableBitVector : BitVector {
    /** Sets [index] to [value], subject to the receiver's bounded or unbounded index contract. */
    @Throws(IndexOutOfBoundsException::class)
    operator fun set(index: Long, value: Boolean)
}

/** A fixed-size mutable bit vector. */
interface MutableBoundedBitVector : BoundedBitVector, MutableBitVector

/** A mutable bit vector that grows when a previously unrepresented nonnegative index is set. */
interface MutableUnboundedBitVector : UnboundedBitVector, MutableBitVector

private fun BitVector.bitIterator(size: Long): Iterator<Boolean> = object : Iterator<Boolean> {
    private var index = 0L

    override fun hasNext(): Boolean = index < size

    override fun next(): Boolean {
        if (!hasNext()) throw NoSuchElementException()
        return get(index++)
    }
}

/** Returns the LSB0 bit at [index], or `false` when [index] exceeds this array. */
@Throws(IndexOutOfBoundsException::class)
fun ByteArray.getLsb0Bit(index: Long): Boolean {
    if (index < 0) throw IndexOutOfBoundsException("index = $index")
    val byteIndex = index / 8
    return byteIndex < size && (this[byteIndex.toInt()] and BitVector.getLsb0Mask(index)) != 0.toByte()
}

/** Returns the MSB0 bit at [index], or `false` when [index] exceeds this array. */
@Throws(IndexOutOfBoundsException::class)
fun ByteArray.getMsb0Bit(index: Long): Boolean {
    if (index < 0) throw IndexOutOfBoundsException("index = $index")
    val byteIndex = index / 8
    return byteIndex < size && (this[byteIndex.toInt()] and BitVector.getMsb0Mask(index)) != 0.toByte()
}

/** Returns the LSB0 bit at [index], or `false` when [index] exceeds this list. */
@Throws(IndexOutOfBoundsException::class)
internal fun List<Byte>.getLsb0Bit(index: Long): Boolean {
    if (index < 0) throw IndexOutOfBoundsException("index = $index")
    val byteIndex = index / 8
    return byteIndex < size && (this[byteIndex.toInt()] and BitVector.getLsb0Mask(index)) != 0.toByte()
}


/** Returns this byte with the order of all eight bits reversed. */
fun Byte.reverseBits(): Byte {
    var value = toInt() and 0xff
    value = ((value and 0x55) shl 1) or ((value ushr 1) and 0x55)
    value = ((value and 0x33) shl 2) or ((value ushr 2) and 0x33)
    return (((value and 0x0f) shl 4) or ((value ushr 4) and 0x0f)).toByte()
}

/**
 * Returns a diagnostic view of this array's physical byte contents.
 *
 * Bytes appear in array-index order, starting with byte `0`. Within every byte, characters appear in conventional
 * binary notation from the most-significant physical bit (`b7`) to the least-significant physical bit (`b0`). Adjacent
 * bytes are separated by one space; an empty array produces an empty string.
 *
 * This function does not apply an LSB0 or MSB0 interpretation. In particular, it does not reverse bits, remove trailing
 * zeroes, or hide padding bits. The same physical byte therefore has the same dump regardless of how a bit vector maps
 * logical indexes onto it:
 *
 * ```text
 * array index        byte 0                         byte 1
 * physical bit       b7 b6 b5 b4 b3 b2 b1 b0       b7 b6 b5 b4 b3 b2 b1 b0
 * MSB0 bit index      0  1  2  3  4  5  6  7        8  9 10 11 12 13 14 15
 * LSB0 bit index      7  6  5  4  3  2  1  0       15 14 13 12 11 10  9  8
 * dump order         ───────────────────────►      ───────────────────────►
 * ```
 *
 * Examples:
 *
 * ```kotlin
 * byteArrayOf().memDumpView()                 // ""
 * byteArrayOf(4).memDumpView()                // "00000100"
 * byteArrayOf(7).memDumpView()                // "00000111"
 * byteArrayOf(17, 31).memDumpView()           // "00010001 00011111"
 * byteArrayOf(0x81.toByte(), 2).memDumpView() // "10000001 00000010"
 * ```
 */
fun ByteArray.memDumpView(): String =
    joinToString(separator = " ") { it.toUByte().toString(2).padStart(8, '0') }

/** Sets [index]. */
fun MutableBitVector.set(index: Long) { this[index] = true }
fun MutableBitVector.set(index: Int) = set(index.toLong())
operator fun BitVector.get(index: Int): Boolean = this[index.toLong()]
operator fun MutableBitVector.set(index: Int, value: Boolean) { this[index.toLong()] = value }

/** Inverts [index]. */
fun MutableBitVector.flip(index: Long) { this[index] = !this[index] }
fun MutableBitVector.flip(index: Int) = flip(index.toLong())

/** Clears [index]. */
fun MutableBitVector.clear(index: Long) { this[index] = false }
fun MutableBitVector.clear(index: Int) = clear(index.toLong())
fun MutableBitVector.flip(fromIndex: Long, toIndex: Long) = flip(fromIndex..toIndex)
fun MutableBitVector.flip(indexes: LongRange) = indexes.forEach { flip(it) }
fun MutableBitVector.set(fromIndex: Long, toIndex: Long) = set(fromIndex..toIndex)
fun MutableBitVector.set(indexes: LongRange) = indexes.forEach { set(it) }
fun MutableBitVector.clear(fromIndex: Long, toIndex: Long) = clear(fromIndex..toIndex)
fun MutableBitVector.clear(indexes: LongRange) = indexes.forEach { clear(it) }
