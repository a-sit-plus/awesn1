// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1

import at.asitplus.awesn1.BitVector.Companion.getByteIndexUnsafe
import kotlin.experimental.and


fun Byte.getBit(index: Int): Boolean =
    if (index !in 0..7) throw IndexOutOfBoundsException("bit index $index out of bounds.")
    else (((1 shl index).toByte() and this) != 0.toByte())


interface MutableBitVector : BitVector {
    operator fun set(index: Long, value: Boolean)
}

interface BitVector : Iterable<Boolean> {


    /**
     * Creates a deep copy of the current `BitVector` instance.
     *
     * @return A new `BitSet` object containing the same state as the current one.
     */
    fun copyOf(): BitVector

    /**
     * Read-Only iterator
     */
    val byteIterator: ByteIterator


    /**
     * Returns the bit at [index]. Never throws an exception when [index]>=0, as getting a bit outside the underlying
     * bytes' bounds returns false.
     */
    operator fun get(index: Long): Boolean

    /**
     * Returns the first bit set to true from [fromIndex] *(= inclusive)*.
     * @return the index of the first bit set to true, or -1 if there are no bits set to true
     */
    fun nextSetBit(fromIndex: Long): Long

    /**
     * Returns the first bit set to true *after* [index] (= exclusive).
     * @return the index of the first bit set to true, or -1 if there are no bits set to true
     */
    fun nextSetBitAfter(index: Long): Long = nextSetBit(index + 1)


    /**
     * Iterates over each bit in the `BitSet` and invokes the provided [action] for every index and corresponding bit value.
     *
     * Deliberatelly not an extension function, to have precedence over the int-indexed `forEach` function of the `Iterable` interface.
     *
     * @param action A lambda function that is invoked with two arguments:
     * - `i`: The index of the bit in the `BitSet`.
     * - `it`: The value of the bit at the given index, either `true` or `false`.
     */
    //deliberately not an extension function
    fun forEachIndexed(action: (i: Long, it: Boolean) -> Unit) {
        for (i in 0..highestSetIndex()) action(i, this[i])
    }

    /**
     * Allocates a fresh byte array and writes the values of this bitset's underlying bytes to it
     */
    fun toByteArray(): ByteArray


    fun highestSetIndex(): Long

    /**
     * Returns all bits as they are accessible by the global bit index
     *
     * Note that this representation conflicts with the usual binary representation of a bit-set's
     * underlying byte array for the following reason:
     *
     * Printing a byte array usually shows the MS*Byte* at the right-most position, but each byte's MS*Bit*
     * at a byte's individual left-most position, leading to bit and byte indices running in opposing directions.
     *
     * The string representation returned by this function can simply be interpreted as a list of boolean values
     * accessible by a monotonic index running in one direction.
     *
     * See the following illustration of memory layout vs. bit string index and the resulting string:
     * ```
     * ┌──────────────────────────────┐
     * │                              │
     * │                              │ Addr: 2
     * │   0  0  0  0  1  1  0  1    │
     * │ ◄─23─22─21─20─19─18─17─16─┐  │
     * │                           │  │
     * ├─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ┤
     * │                           │  │
     * │ ┌─────────────────────────┘  │ Addr: 1
     * │ │  1  0  0  0  1  0  0  0    │
     * │ └─15─14─12─12─11─10──9──8─┐  │
     * │                           │  │
     * ├─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ┤
     * │                           │  │
     * │ ┌─────────────────────────┘  │ Addr: 0
     * │ │  1  0  1  1  0  1  1  1    │
     * │ └──7──6──5──4──3──2──1──0──────index─◄─
     * │                              │
     * └──────────────────────────────┘
     *```
     *
     * This leads to the following bit string:
     * 11101101000100011011
     */
    fun toBitStringView() = toByteArray().toBitStringView()

    /**
     * Returns a binary representation of this bit set's memory layout, when packed into a byte array
     * Bytes are separated by a single space. An empty byte array results in an empty string.
     *
     * ```kotlin
     * val bits = BitSet()
     * bits[2] = true                   //00000100
     * bits[1] = true                   //00000110
     * bits[0] = true                   //00000111
     * bits[8] = true                   //00000111 00000001
     * ```
     */
    fun memDumpView() = toByteArray().memDumpView()


    /**
     * returns an iterator over bits. use [bytes]`.iterator()` to iterate over bytes
     */
    override fun iterator(): Iterator<Boolean> = object : Iterator<Boolean> {
        var index = 0L
        override fun hasNext(): Boolean = index <= highestSetIndex()
        override fun next(): Boolean = get(index++)
    }

    companion object {
        internal fun getByteIndex(i: Long) = (i / 8).toNonnegativeIntChecked("BitSet byte index")
        internal fun getBitIndex(i: Long) = (i % 8).toInt()

        internal fun Any.getByteIndexUnsafe(index: Long): Int {
            if (index < 0) throw IndexOutOfBoundsException("index = $index")
            val byteIndex = index / 8
            if (byteIndex >= (if (this is ByteArray) size else (this as List<*>).size)) return -1
            return byteIndex.toInt()
        }
    }
}

fun ByteArray.getBit(index: Long): Boolean {
    context(BitVector.Companion) {
        val byteIndex = this.getByteIndexUnsafe(index)
        return this[byteIndex].getBit(BitVector.getBitIndex(index))
    }
}


fun List<Byte>.getBit(index: Long): Boolean {
    context(BitVector.Companion) {
        val byteIndex = this.getByteIndexUnsafe(index)
        return this[byteIndex].getBit(BitVector.getBitIndex(index))
    }
}


/**
 * Returns all bits as they are accessible by the global bit index (i.e. after wrapping this ByteArray into a BitSet)
 *
 * Note that this representation conflicts with the usual binary representation of a byte array for the following reason:
 *
 * Printing a byte array usually shows the MS*Byte* at the right-most position, but each byte's MS*Bit*
 * at a byte's individual left-most position, leading to bit and byte indices running in opposing directions.
 *
 * The string representation returned by this function can simply be interpreted as a list of boolean values
 * accessible by a monotonic index running in one direction.
 *
 * See the following illustration of memory layout vs. bit string index and the resulting string:
 * ```
 * ┌──────────────────────────────┐
 * │                              │
 * │                              │ Addr: 2
 * |    0  0  0  0  1  1  0  1    │
 * │ ◄─23─22─21─20─19─18─17─16─┐  │
 * │                           │  │
 * ├─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ┤
 * │                           │  │
 * │ ┌─────────────────────────┘  │ Addr: 1
 * │ │  1  0  0  0  1  0  0  0    │
 * │ └─15─14─12─12─11─10──9──8─┐  │
 * │                           │  │
 * ├─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ┤
 * │                           │  │
 * │ ┌─────────────────────────┘  │ Addr: 0
 * │ │  1  0  1  1  0  1  1  1    │
 * │ └──7──6──5──4──3──2──1──0──────index─◄─
 * │                              │
 * └──────────────────────────────┘
 *```
 *
 * This leads to the following bit string:
 * 11101101000100011011
 */
fun ByteArray.toBitStringView(): String =
    joinToString(separator = "") {
        it.toUByte().toString(2).padStart(8, '0').reversed()
    }.dropLastWhile { it == '0' }

/**
 * Returns a binary representation of this byte array's memory layout
 * Bytes are separated by a single space. An empty byte array results in an empty string.
 *
 * ```kotlin
 * byteArrayOf(4).memDump()         //00000100
 * byteArrayOf(7).memDump()         //00000111
 * byteArrayOf(17, 31).memDump()    //00010001 00011111
 * ```
 */
fun ByteArray.memDumpView(): String =
    joinToString(separator = " ") { it.toUByte().toString(2).padStart(8, '0') }


/**
 * shorthand for `set(index, true)`
 */
fun MutableBitVector.set(index: Long) {
    this[index] = true
}

fun MutableBitVector.set(index: Int) = set(index.toLong())


operator fun BitVector.get(index: Int): Boolean = this[index.toLong()]
operator fun MutableBitVector.set(index: Int, value: Boolean) {
    this[index.toLong()] = value
}

fun MutableBitVector.flip(index: Long) {
    this[index] = !this[index]
}

fun MutableBitVector.flip(index: Int) = flip(index.toLong())

/**
 * shorthand for `set(index, false)`
 */
fun MutableBitVector.clear(index: Long) {
    this[index] = false
}

fun MutableBitVector.clear(index: Int) = clear(index.toLong())

fun MutableBitVector.flip(fromIndex: Long, toIndex: Long) = flip(LongRange(fromIndex, toIndex))
fun MutableBitVector.flip(indexes: LongRange) = indexes.forEach { flip(it) }
fun MutableBitVector.set(fromIndex: Long, toIndex: Long) = set(LongRange(fromIndex, toIndex))
fun MutableBitVector.set(indexes: LongRange) = indexes.forEach { set(it) }
fun MutableBitVector.clear(fromIndex: Long, toIndex: Long) = clear(LongRange(fromIndex, toIndex))
fun MutableBitVector.clear(longRange: LongRange) = longRange.forEach { clear(it) }
