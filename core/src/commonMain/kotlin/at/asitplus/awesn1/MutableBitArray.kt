// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1

import at.asitplus.awesn1.BitVector.Companion.getByteIndex
import kotlin.experimental.and
import kotlin.experimental.inv
import kotlin.experimental.or


class BitArray(private val impl: MutableBitArray) : BitVector by impl {
    companion object {

        //yes, int, because if you want more, init using a bytearray!
        operator fun invoke(nBits: Int, initializer: (Int) -> Boolean): BitArray =
            BitArray(MutableBitArray(nBits.toLong()).apply {
                repeat(nBits) {
                    if (initializer(it)) set(it.toLong())
                }
            })

        operator fun invoke(vararg bits: Boolean): BitArray =
            invoke(bits.size) { bits[it] }

        /**
         * Wraps [bytes] into a BitSet. Copies all bytes.
         * Hence, modifications to [bytes] are **not** reflected in the newly created BitSet.
         */
        fun wrap(bytes: ByteArray) = BitArray(MutableBitArray(bytes))

        /**
         * Deep-copies the [byteArray] into a [MutableBitArray]
         */
        operator fun invoke(byteArray: ByteArray): BitArray = wrap(byteArray.copyOf())

        /**
         * Creates bitset from hunan-readably bit string representation
         * @throws IllegalArgumentException if the provided string contains characters other than '1' and '0'
         */
        @Throws(IllegalArgumentException::class)
        fun fromString(stringRepresentation: String): BitArray {
            if (stringRepresentation.isEmpty()) return BitArray(0) { false }
            if (!stringRepresentation.matches(Regex("^[01]+\$"))) throw IllegalArgumentException("Not a bit string")
            return invoke(stringRepresentation.length) { stringRepresentation[it] == '1' }
        }

        /**
         * Exception-free version of [fromString]
         */
        fun fromBitStringOrNull(bitString: String) : BitArray? = catchingUnwrapped { fromString(bitString) }.getOrNull()
    }
}

class MutableBitArray private constructor(private val buffer: ByteArray) : MutableBitVector {


    /**
     * Creates a deep copy of the current `BitSet` instance.
     *
     * @return A new `BitSet` object containing the same state as the current one.
     */
    override fun copyOf(): MutableBitArray = MutableBitArray(buffer.copyOf())
    override val byteIterator: ByteIterator
        get() = object : ByteIterator() {
            var index = 0
            override fun nextByte(): Byte {
                return buffer[index++]
            }

            override fun hasNext(): Boolean {
                return index < buffer.size - 1
            }
        }

    /**
     * Preallocates a buffer capable of holding [nBits] many bits
     */
    constructor(nBits: Long = 0) : this(
        if (nBits < 0) throw IllegalArgumentException("a bit set of size $nBits makes no sense")
        else with(BitVector.Companion) {
            ByteArray((getByteIndex(nBits).toLong() + 1).toNonnegativeIntChecked("BitSet preallocate size"))
        })


    /**
     * Returns the bit at [index]. Never throws an exception when [index]>=0, as getting a bit outside the underlying
     * bytes' bounds returns false.
     */
    override operator fun get(index: Long): Boolean = buffer.getBit(index)

    /**
     * Returns the first bit set to true from [fromIndex] *(= inclusive)*.
     * @return the index of the first bit set to true, or -1 if there are no bits set to true
     * @throws when [fromIndex] exceeds the underlying array's capacity
     */
    @Throws(IndexOutOfBoundsException::class)
    override fun nextSetBit(fromIndex: Long): Long {
        if (fromIndex < 0) throw IndexOutOfBoundsException("fromIndex = $fromIndex")
        val byteIndex = getByteIndex(fromIndex)
        if (byteIndex > buffer.lastIndex) throw IndexOutOfBoundsException("fromIndex = $fromIndex, size = ${buffer.size.toLong() * 8}")
        else {
            val startIndex = with(BitVector.Companion) { getBitIndex(fromIndex).toLong() }
            for (i: Long in startIndex until buffer.size.toLong() * 8L) {
                if (buffer.getBit(i)) return byteIndex.toLong() * 8L + i
            }

            return -1
        }
    }

    /**
     * Returns the first bit set to true *after* [index] (= exclusive).
     * @return the index of the first bit set to true, or -1 if there are no bits set to true
     * @throws when [fromIndex] exceeds the underlying array's capacity
     */
    @Throws(IndexOutOfBoundsException::class)
    override fun nextSetBitAfter(index: Long): Long = nextSetBit(index + 1)

    /**
     * The maximum capacity in Bits this [MutableBitArray] can carry.
     */
    val capacity: Long get() = buffer.size.toLong() * 8

    /**
     * Sets the bit at [index] to [value]
     */
    override operator fun set(index: Long, value: Boolean) {
        val byteIndex = getByteIndex(index)
        if (byteIndex > buffer.lastIndex) throw IndexOutOfBoundsException("fromIndex = $index, size = ${buffer.size.toLong() * 8}")
        val byte = buffer[byteIndex]
        with(BitVector.Companion) {
            buffer[byteIndex] =
                if (value) {
                    ((1 shl getBitIndex(index)).toByte() or byte)
                } else
                    ((1 shl getBitIndex(index)).toByte().inv() and byte)
        }
    }

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
    override fun forEachIndexed(action: (i: Long, it: Boolean) -> Unit) {
        for (i in 0..highestSetIndex()) action(i, this[i])
    }

    /**
     * Allocates a fresh byte array and writes the values of this bitset's underlying bytes to it
     */
    override fun toByteArray(): ByteArray {
        return if (buffer.isEmpty()) byteArrayOf()
        else buffer.copyOf()
    }


    override fun highestSetIndex(): Long {
        for (i: Long in buffer.size.toLong() * 8L - 1L downTo 0L) {
            if (buffer.getBit(i)) return i
        }
        return -1L
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is MutableBitArray) return false
        return buffer.contentEquals(other.buffer)
    }

    override fun hashCode(): Int = toByteArray().contentHashCode()


    companion object {

        //yes, int, because if you want more, init using a bytearray!
        operator fun invoke(nBits: Int, initializer: (Int) -> Boolean): MutableBitArray =
            MutableBitArray(nBits.toLong()).apply {
                repeat(nBits) {
                    if (initializer(it)) set(it.toLong())
                }
            }

        operator fun invoke(vararg bits: Boolean) =
            invoke(bits.size) { bits[it] }

        /**
         * Wraps [bytes] into a BitSet. Copies all bytes.
         * Hence, modifications to [bytes] are **not** reflected in the newly created BitSet.
         */
        fun wrap(bytes: ByteArray) = MutableBitArray(bytes)

        /**
         * Deep-copies the [byteArray] into a [MutableBitArray]
         */
        operator fun invoke(byteArray: ByteArray): MutableBitArray = wrap(byteArray.copyOf())

        /**
         * Creates bitset from hunan-readably bit string representation
         * @throws IllegalArgumentException if the provided string contains characters other than '1' and '0'
         */
        @Throws(IllegalArgumentException::class)
        fun fromString(stringRepresentation: String): MutableBitArray {
            if (stringRepresentation.isEmpty()) return MutableBitArray(0)
            if (!stringRepresentation.matches(Regex("^[01]+\$"))) throw IllegalArgumentException("Not a bit string")
            return invoke(stringRepresentation.length) { stringRepresentation[it] == '1' }
        }

        /**
         * Exception-free version of [fromString]
         */
        fun fromBitStringOrNull(bitString: String) = catchingUnwrapped { fromString(bitString) }.getOrNull()
    }
}

/**
 * copies this byteArray into a [BitSet]
 */
fun ByteArray.toBitArray(): MutableBitArray = MutableBitArray(this)
