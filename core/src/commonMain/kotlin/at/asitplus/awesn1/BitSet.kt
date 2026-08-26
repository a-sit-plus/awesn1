// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1

import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.InvocationKind
import kotlin.contracts.contract
import kotlin.experimental.and
import kotlin.experimental.inv
import kotlin.experimental.or
/**
 * A growing, pure-Kotlin bit set modelled after Java's `java.util.BitSet`.
 *
 * Every nonnegative index is valid. Its finite logical view ends after [highestSetIndex], so unset bits above the
 * highest set bit are not represented when iterating or serializing. Use [toLsb0ByteArray] for Java `BitSet`-compatible
 * bytes and [toMsb0ByteArray] when index zero must use mask `0x80` within each byte.
 */
class BitSet private constructor(private val buffer: MutableList<Byte>) :
    MutableUnboundedCompactingBitVector {

    /**
     * Mutates the compact backing bytes in place using LSB0 order. Byte zero holds logical indexes `0..7`, and logical
     * index zero uses mask `0x01`.
     *
     * The receiver is a live view and must not be retained after [action] returns. Trailing zero bytes are removed before
     * and after the action, including when it throws; mutations made before an exception remain applied.
     */
    @OptIn(ExperimentalContracts::class)
    fun mutateLsb0Bytes(action: MutableList<Byte>.() -> Unit) {
        contract { callsInPlace(action, InvocationKind.EXACTLY_ONCE) }
        compact()
        try {
            buffer.action()
        } finally {
            compact()
        }
    }

    /**
     * Preallocates enough storage for [nBits] without changing this set's logical contents.
     *
     * @throws IllegalArgumentException if [nBits] is negative
     * @throws Asn1Exception if the required byte count cannot be represented
     */
    @Throws(IllegalArgumentException::class, Asn1Exception::class)
    constructor(nBits: Long = 0) : this(MutableList(BitVector.getByteCount(nBits)) { 0 })

    /** Returns the bit at [index], or `false` for any unset nonnegative index. */
    override fun get(index: Long): Boolean = buffer.getLsb0Bit(index)

    /** Returns the first set bit at or after [fromIndex], or `-1`. */
    override fun nextSetBit(fromIndex: Long): Long {
        if (fromIndex < 0) throw IndexOutOfBoundsException("fromIndex = $fromIndex")
        val last = highestSetIndex()
        if (fromIndex > last) return -1
        for (index in fromIndex..last) if (get(index)) return index
        return -1
    }

    /** Sets or clears [index], growing the backing storage when necessary. */
    override fun set(index: Long, value: Boolean) {
        val byteIndex = BitVector.getByteIndex(index)
        while (buffer.size <= byteIndex) buffer.add(0)
        val mask = BitVector.getLsb0Mask(index)
        buffer[byteIndex] = if (value) buffer[byteIndex] or mask else buffer[byteIndex] and mask.inv()
        if (!value) compact()
    }

    /** Invokes [action] for logical indexes zero through [highestSetIndex]. */
    fun forEachIndexed(action: (index: Long, bit: Boolean) -> Unit) {
        for (index in 0..highestSetIndex()) action(index, get(index))
    }

    /** Returns compact Java `BitSet`-compatible LSB0 bytes. */
    override fun toLsb0ByteArray(): ByteArray {
        compact()
        return buffer.toByteArray()
    }

    /** Returns compact MSB0 bytes*/
    override fun toMsb0ByteArray(): ByteArray {
        compact()
        return ByteArray(buffer.size) { buffer[it].reverseBits() }
    }

    /** Iterates compact Java `BitSet`-compatible LSB0 bytes without allocating a byte array. */
    override fun lsb0ByteIterator(): ByteIterator = byteIterator(reverseBits = false)

    /** Iterates compact MSB0 bytes without allocating a byte array. */
    override fun msb0ByteIterator(): ByteIterator = byteIterator(reverseBits = true)

    private fun byteIterator(reverseBits: Boolean): ByteIterator {
        compact()
        val initialSize = buffer.size
        return object : ByteIterator() {
            private var index = 0

            override fun hasNext(): Boolean {
                if (buffer.size != initialSize) throw ConcurrentModificationException()
                return index < initialSize
            }

            override fun nextByte(): Byte {
                if (!hasNext()) throw NoSuchElementException()
                return buffer[index++].let { if (reverseBits) it.reverseBits() else it }
            }
        }
    }

    /** Returns a physical dump of the compact native LSB0 backing bytes. */
    fun memDumpView(): String = toLsb0ByteArray().memDumpView()

    override fun highestSetIndex(): Long {
        compact()
        for (index in buffer.size.toLong() * 8 - 1 downTo 0) if (buffer.getLsb0Bit(index)) return index
        return -1
    }

    private fun compact() {
        while (buffer.lastOrNull() == 0.toByte()) buffer.removeAt(buffer.lastIndex)
    }

    override fun equals(other: Any?): Boolean =
        this === other || other is BitSet && toLsb0ByteArray().contentEquals(other.toLsb0ByteArray())

    override fun hashCode(): Int = toLsb0ByteArray().contentHashCode()

    companion object {
        /** Creates a set from [nBits] initializer values; trailing false values do not define a size. */
        operator fun invoke(nBits: Int, initializer: (Int) -> Boolean): BitSet = BitSet(nBits.toLong()).apply {
            for (index in 0 until nBits) if (initializer(index)) set(index)
        }

        operator fun invoke(vararg bits: Boolean): BitSet = invoke(bits.size) { bits[it] }

        /** Copies Java `BitSet`-compatible LSB0 [bytes] into a new bit set. */
        operator fun invoke(bytes: ByteArray): BitSet = BitSet(bytes.toMutableList())

        /** Creates a bit set from logical indexes written left-to-right as `0` and `1`. */
        @Throws(IllegalArgumentException::class)
        fun fromLogicalBitString(value: String): BitSet {
            require(value.all { it == '0' || it == '1' }) { "Not a logical bit string" }
            return invoke(value.length) { value[it] == '1' }
        }

        /** Returns `null` instead of throwing for an invalid logical bit string. */
        fun fromLogicalBitStringOrNull(value: String): BitSet? =
            catchingUnwrapped { fromLogicalBitString(value) }.getOrNull()
    }
}


/** Copies Java `BitSet`-compatible LSB0 bytes into a [BitSet]. */
fun ByteArray.toBitSet(): BitSet = BitSet(this)

/**
 * Creates an independent [BitSet] containing the same set logical indexes. As [BitSet] is unbounded, this conversion
 * intentionally loses trailing unset bits and the exact [logicalBitCount].
 */
fun FixedSizeBitVector.toBitSet(): BitSet = BitSet(logicalBitCount).also { result ->
    for (index in 0 until logicalBitCount) if (get(index)) result.set(index)
}


/**
 * Creates an independent [BitSet] containing the same set logical indexes. As [BitSet] is unbounded, this conversion
 * intentionally loses trailing unset bits and the exact [logicalBitCount].
 */
fun FixedSizeBitVector.toUnboundedCompactingBitVector(): UnboundedCompactingBitVector = toBitSet()
