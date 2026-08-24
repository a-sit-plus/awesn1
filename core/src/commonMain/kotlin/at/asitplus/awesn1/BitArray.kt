// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1

import kotlin.experimental.and
import kotlin.experimental.inv
import kotlin.experimental.or

/**
 * Read-only fixed-size bits backed by a [ByteArray]. [Msb0BitArray] and [Lsb0BitArray] mark the native [bitOrder].
 * Unset bits at the end remain represented and are returned by [iterator].
 *
 * [wrap] deliberately aliases its input. This is a read-only view, not an immutable value; use [invoke] to copy.
 */
sealed class BitArray protected constructor(
    protected val buffer: ByteArray,
    open val bitOrder: BitVector.BitOrder,
    final override val logicalBitCount: Long,
) : FixedSizeBitVector {

    init {
        require(BitVector.getByteCount(logicalBitCount) == buffer.size) {
            "logicalBitCount = $logicalBitCount requires ${BitVector.getByteCount(logicalBitCount)} bytes, found ${buffer.size}"
        }
    }
    override fun get(index: Long): Boolean {
        checkIndex(index)
        return when (bitOrder) {
            BitVector.BitOrder.LSB0 -> buffer.getLsb0Bit(index)
            BitVector.BitOrder.MSB0 -> buffer.getMsb0Bit(index)
        }
    }

    override fun nextSetBit(fromIndex: Long): Long {
        if (fromIndex < 0) throw IndexOutOfBoundsException("fromIndex = $fromIndex")
        for (index in fromIndex until logicalBitCount) if (get(index)) return index
        return -1
    }

    override fun highestSetIndex(): Long {
        for (index in logicalBitCount - 1 downTo 0) if (get(index)) return index
        return -1
    }

    /** Returns the represented logical bits in LSB0 layout. */
    override fun toLsb0ByteArray(): ByteArray = bytes(BitVector.BitOrder.LSB0)

    /** Returns the represented logical bits in MSB0 layout. */
    override fun toMsb0ByteArray(): ByteArray = bytes(BitVector.BitOrder.MSB0)

    /** Iterates the represented logical bits packed in LSB0 layout. */
    override fun lsb0ByteIterator(): ByteIterator =
        buffer.byteIterator(bitOrder, BitVector.BitOrder.LSB0, logicalBitCount)

    /** Iterates the represented logical bits packed in MSB0 layout. */
    override fun msb0ByteIterator(): ByteIterator =
        buffer.byteIterator(bitOrder, BitVector.BitOrder.MSB0, logicalBitCount)

    /** Invokes [action] for every represented bit, including unset bits. */
    fun forEachIndexed(action: (index: Long, bit: Boolean) -> Unit) {
        for (index in 0 until logicalBitCount) action(index, get(index))
    }

    /** Returns a physical dump of the native backing bytes. */
    fun memDumpView(): String = buffer.memDumpView()

    private fun bytes(order: BitVector.BitOrder): ByteArray =
        (if (order == bitOrder) buffer.copyOf() else ByteArray(buffer.size) { buffer[it].reverseBits() })
            .maskUnusedBits(logicalBitCount, order)

    protected fun checkIndex(index: Long) {
        if (index !in 0 until logicalBitCount) {
            throw IndexOutOfBoundsException("index = $index, logicalBitCount = $logicalBitCount")
        }
    }

    protected fun mask(index: Long): Byte = when (bitOrder) {
        BitVector.BitOrder.LSB0 -> BitVector.getLsb0Mask(index)
        BitVector.BitOrder.MSB0 -> BitVector.getMsb0Mask(index)
    }

    /** Creates an independent mutable array with the same orientation, extent, and logical contents. */
    fun toMutableBitArray(): MutableBitArray =
        MutableBitArray.wrap(bitOrder, buffer.copyOf(), logicalBitCount)

    private fun logicalBytes(): ByteArray = toLsb0ByteArray().also { bytes ->
        val usedBits = (logicalBitCount % 8).toInt()
        if (usedBits != 0) bytes[bytes.lastIndex] = bytes.last() and ((1 shl usedBits) - 1).toByte()
    }

    override fun equals(other: Any?): Boolean =
        this === other || other is BitArray && logicalBitCount == other.logicalBitCount &&
                logicalBytes().contentEquals(other.logicalBytes())

    override fun hashCode(): Int = 31 * logicalBitCount.hashCode() + logicalBytes().contentHashCode()

    companion object {
        /** Creates exactly [nBits] initialized logical bits using the required native [bitOrder]. */
        operator fun invoke(bitOrder: BitVector.BitOrder, nBits: Int, initializer: (Int) -> Boolean): BitArray {
            val buffer = ByteArray(BitVector.getByteCount(nBits.toLong()))
            repeat(nBits) { index ->
                if (initializer(index)) {
                    val mask = when (bitOrder) {
                        BitVector.BitOrder.LSB0 -> BitVector.getLsb0Mask(index.toLong())
                        BitVector.BitOrder.MSB0 -> BitVector.getMsb0Mask(index.toLong())
                    }
                    buffer[index / 8] = buffer[index / 8] or mask
                }
            }
            return wrap(bitOrder, buffer, nBits.toLong())
        }

        /** Creates exactly [nBits] initialized logical bits using the required native [bitOrder]. */
        operator fun invoke(bitOrder: BitVector.BitOrder, nBits: Long, initializer: (Long) -> Boolean): BitArray {
            val buffer = ByteArray(BitVector.getByteCount(nBits))
            for (index in 0L until nBits) {
                if (initializer(index)) {
                    val mask = when (bitOrder) {
                        BitVector.BitOrder.LSB0 -> BitVector.getLsb0Mask(index)
                        BitVector.BitOrder.MSB0 -> BitVector.getMsb0Mask(index)
                    }
                    buffer[(index / 8).toInt()] = buffer[(index / 8).toInt()] or mask
                }
            }
            return wrap(bitOrder, buffer, nBits)
        }

        /** Creates one represented logical bit for every value in [bits]. */
        operator fun invoke(bitOrder: BitVector.BitOrder, vararg bits: Boolean): BitArray =
            invoke(bitOrder, bits.size) { bits[it] }

        /** Wraps [bytes] without copying as exactly [logicalBitCount] logical bits in native [bitOrder]. */
        fun wrap(
            bitOrder: BitVector.BitOrder,
            bytes: ByteArray,
            logicalBitCount: Long = bytes.size.toLong() * 8,
        ): BitArray = when (bitOrder) {
            BitVector.BitOrder.LSB0 -> DefaultLsb0BitArray(bytes, logicalBitCount)
            BitVector.BitOrder.MSB0 -> DefaultMsb0BitArray(bytes, logicalBitCount)
        }

        /** Copies [byteArray] into a fixed-size bit array using its declared native [bitOrder]. */
        operator fun invoke(
            bitOrder: BitVector.BitOrder,
            byteArray: ByteArray,
            logicalBitCount: Long = byteArray.size.toLong() * 8,
        ): BitArray = wrap(bitOrder, byteArray.copyOf(), logicalBitCount)

        /** Creates a fixed-size array from logical indexes written left-to-right as `0` and `1`. */
        @Throws(IllegalArgumentException::class)
        fun fromLogicalBitString(value: String, bitOrder: BitVector.BitOrder): BitArray {
            require(value.all { it == '0' || it == '1' }) { "Not a logical bit string" }
            return invoke(bitOrder, value.length) { value[it] == '1' }
        }

        /** Returns `null` instead of throwing for an invalid logical bit string. */
        fun fromLogicalBitStringOrNull(value: String, bitOrder: BitVector.BitOrder): BitArray? =
            catchingUnwrapped { fromLogicalBitString(value, bitOrder) }.getOrNull()
    }
}

/**
 * Mutable fixed-size bits backed by a [ByteArray]. Valid indexes are exactly `0..<logicalBitCount`; reads and writes
 * outside that logical domain throw. [MutableMsb0BitArray] and [MutableLsb0BitArray] make the native [bitOrder]
 * explicit while remaining true subclasses of both [MutableBitArray] and [BitArray].
 */
sealed class MutableBitArray protected constructor(
    buffer: ByteArray,
    bitOrder: BitVector.BitOrder,
    logicalBitCount: Long,
) : BitArray(buffer, bitOrder, logicalBitCount), MutableFixedSizeBitVector {

    override fun set(index: Long, value: Boolean) {
        checkIndex(index)
        val byteIndex = BitVector.getByteIndex(index)
        val mask = mask(index)
        buffer[byteIndex] = if (value) buffer[byteIndex] or mask else buffer[byteIndex] and mask.inv()
    }

    companion object {
        /** Creates exactly [nBits] unset bits using the required native [bitOrder]. */
        @Throws(IllegalArgumentException::class, Asn1Exception::class)
        operator fun invoke(bitOrder: BitVector.BitOrder, nBits: Long = 0): MutableBitArray =
            wrap(bitOrder, ByteArray(BitVector.getByteCount(nBits)), nBits)

        /** Creates exactly [nBits] initialized logical bits using the required native [bitOrder]. */
        operator fun invoke(bitOrder: BitVector.BitOrder, nBits: Int, initializer: (Int) -> Boolean): MutableBitArray =
            invoke(bitOrder, nBits.toLong()).apply {
                for (index in 0 until nBits) if (initializer(index)) set(index)
            }
        /** Creates exactly [nBits] initialized logical bits using the required native [bitOrder]. */
        operator fun invoke(
            bitOrder: BitVector.BitOrder,
            nBits: Long,
            initializer: (Long) -> Boolean
        ): MutableBitArray =
            invoke(bitOrder, nBits).apply {
                for (index in 0 until nBits) if (initializer(index)) set(index)
            }
        /** Creates one represented logical bit for every value in [bits]. */
        operator fun invoke(bitOrder: BitVector.BitOrder, vararg bits: Boolean): MutableBitArray =
            invoke(bitOrder, bits.size) { bits[it] }

        /** Wraps [bytes] without copying as exactly [logicalBitCount] logical bits in native [bitOrder]. */
        fun wrap(
            bitOrder: BitVector.BitOrder,
            bytes: ByteArray,
            logicalBitCount: Long = bytes.size.toLong() * 8,
        ): MutableBitArray = when (bitOrder) {
            BitVector.BitOrder.LSB0 -> MutableLsb0BitArray.fromBacking(bytes, logicalBitCount)
            BitVector.BitOrder.MSB0 -> MutableMsb0BitArray.fromBacking(bytes, logicalBitCount)
        }

        /** Copies [byteArray] into a fixed-size mutable bit array using its declared native [bitOrder]. */
        operator fun invoke(
            bitOrder: BitVector.BitOrder,
            byteArray: ByteArray,
            logicalBitCount: Long = byteArray.size.toLong() * 8,
        ): MutableBitArray = wrap(bitOrder, byteArray.copyOf(), logicalBitCount)

        /** Creates a mutable fixed-size array from logical indexes written left-to-right as `0` and `1`. */
        @Throws(IllegalArgumentException::class)
        fun fromLogicalBitString(value: String, bitOrder: BitVector.BitOrder): MutableBitArray {
            require(value.all { it == '0' || it == '1' }) { "Not a logical bit string" }
            return invoke(bitOrder, value.length) { value[it] == '1' }
        }

        /** Returns `null` instead of throwing for an invalid logical bit string. */
        fun fromLogicalBitStringOrNull(value: String, bitOrder: BitVector.BitOrder): MutableBitArray? =
            catchingUnwrapped { fromLogicalBitString(value, bitOrder) }.getOrNull()
    }
}

private class DefaultMsb0BitArray(bytes: ByteArray, logicalBitCount: Long) :
    BitArray(bytes, BitVector.BitOrder.MSB0, logicalBitCount), Msb0BitArray {
    override val bitOrder: BitVector.BitOrder get() = BitVector.BitOrder.MSB0
}

private class DefaultLsb0BitArray(bytes: ByteArray, logicalBitCount: Long) :
    BitArray(bytes, BitVector.BitOrder.LSB0, logicalBitCount), Lsb0BitArray {
    override val bitOrder: BitVector.BitOrder get() = BitVector.BitOrder.LSB0
}

/** A mutable MSB0 array. It is both a [MutableBitArray] and an [Msb0BitArray]. */
class MutableMsb0BitArray private constructor(bytes: ByteArray, logicalBitCount: Long) :
    MutableBitArray(bytes, BitVector.BitOrder.MSB0, logicalBitCount), Msb0BitArray {
    override val bitOrder: BitVector.BitOrder get() = BitVector.BitOrder.MSB0

    companion object {
        internal fun fromBacking(bytes: ByteArray, logicalBitCount: Long): MutableMsb0BitArray =
            MutableMsb0BitArray(bytes, logicalBitCount)
    }
}

/** A mutable LSB0 array. It is both a [MutableBitArray] and an [Lsb0BitArray]. */
class MutableLsb0BitArray private constructor(bytes: ByteArray, logicalBitCount: Long) :
    MutableBitArray(bytes, BitVector.BitOrder.LSB0, logicalBitCount), Lsb0BitArray {
    override val bitOrder: BitVector.BitOrder get() = BitVector.BitOrder.LSB0

    companion object {
        internal fun fromBacking(bytes: ByteArray, logicalBitCount: Long): MutableLsb0BitArray =
            MutableLsb0BitArray(bytes, logicalBitCount)
    }
}

/** Copies [byteArray] into a fixed-size MSB0 bit array. */
operator fun Msb0BitArray.Companion.invoke(
    byteArray: ByteArray,
    logicalBitCount: Long = byteArray.size.toLong() * 8,
): Msb0BitArray = DefaultMsb0BitArray(byteArray.copyOf(), logicalBitCount)

/** Wraps [bytes] without copying as exactly [logicalBitCount] logical MSB0 bits. */
fun Msb0BitArray.Companion.wrap(
    bytes: ByteArray,
    logicalBitCount: Long = bytes.size.toLong() * 8,
): Msb0BitArray = DefaultMsb0BitArray(bytes, logicalBitCount)

/** Creates exactly [nBits] initialized logical MSB0 bits. */
operator fun Msb0BitArray.Companion.invoke(nBits: Int, initializer: (Int) -> Boolean): Msb0BitArray =
    BitArray(BitVector.BitOrder.MSB0, nBits, initializer) as Msb0BitArray

/** Creates exactly [nBits] initialized logical MSB0 bits. */
operator fun Msb0BitArray.Companion.invoke(nBits: Long, initializer: (Long) -> Boolean): Msb0BitArray =
    BitArray(BitVector.BitOrder.MSB0, nBits, initializer) as Msb0BitArray

/** Copies [byteArray] into a fixed-size LSB0 bit array. */
operator fun Lsb0BitArray.Companion.invoke(
    byteArray: ByteArray,
    logicalBitCount: Long = byteArray.size.toLong() * 8,
): Lsb0BitArray = DefaultLsb0BitArray(byteArray.copyOf(), logicalBitCount)

/** Wraps [bytes] without copying as exactly [logicalBitCount] logical LSB0 bits. */
fun Lsb0BitArray.Companion.wrap(
    bytes: ByteArray,
    logicalBitCount: Long = bytes.size.toLong() * 8,
): Lsb0BitArray = DefaultLsb0BitArray(bytes, logicalBitCount)

/** Creates exactly [nBits] initialized logical LSB0 bits. */
operator fun Lsb0BitArray.Companion.invoke(nBits: Int, initializer: (Int) -> Boolean): Lsb0BitArray =
    BitArray(BitVector.BitOrder.LSB0, nBits, initializer) as Lsb0BitArray

/** Creates exactly [nBits] initialized logical LSB0 bits. */
operator fun Lsb0BitArray.Companion.invoke(nBits: Long, initializer: (Long) -> Boolean): Lsb0BitArray =
    BitArray(BitVector.BitOrder.LSB0, nBits, initializer) as Lsb0BitArray

/** Copies [byteArray] into a fixed-size mutable MSB0 bit array. */
operator fun MutableMsb0BitArray.Companion.invoke(
    byteArray: ByteArray,
    logicalBitCount: Long = byteArray.size.toLong() * 8,
): MutableMsb0BitArray = MutableMsb0BitArray.fromBacking(byteArray.copyOf(), logicalBitCount)

/** Wraps [bytes] without copying as exactly [logicalBitCount] logical mutable MSB0 bits. */
fun MutableMsb0BitArray.Companion.wrap(
    bytes: ByteArray,
    logicalBitCount: Long = bytes.size.toLong() * 8,
): MutableMsb0BitArray = MutableMsb0BitArray.fromBacking(bytes, logicalBitCount)

/** Creates exactly [nBits] unset mutable MSB0 bits. */
operator fun MutableMsb0BitArray.Companion.invoke(nBits: Long = 0): MutableMsb0BitArray =
    MutableBitArray(BitVector.BitOrder.MSB0, nBits) as MutableMsb0BitArray

/** Creates exactly [nBits] initialized mutable MSB0 bits. */
operator fun MutableMsb0BitArray.Companion.invoke(
    nBits: Int,
    initializer: (Int) -> Boolean,
): MutableMsb0BitArray = MutableBitArray(BitVector.BitOrder.MSB0, nBits, initializer) as MutableMsb0BitArray

/** Creates exactly [nBits] initialized mutable MSB0 bits. */
operator fun MutableMsb0BitArray.Companion.invoke(
    nBits: Long,
    initializer: (Long) -> Boolean,
): MutableMsb0BitArray = MutableBitArray(BitVector.BitOrder.MSB0, nBits, initializer) as MutableMsb0BitArray

/** Copies [byteArray] into a fixed-size mutable LSB0 bit array. */
operator fun MutableLsb0BitArray.Companion.invoke(
    byteArray: ByteArray,
    logicalBitCount: Long = byteArray.size.toLong() * 8,
): MutableLsb0BitArray = MutableLsb0BitArray.fromBacking(byteArray.copyOf(), logicalBitCount)

/** Wraps [bytes] without copying as exactly [logicalBitCount] logical mutable LSB0 bits. */
fun MutableLsb0BitArray.Companion.wrap(
    bytes: ByteArray,
    logicalBitCount: Long = bytes.size.toLong() * 8,
): MutableLsb0BitArray = MutableLsb0BitArray.fromBacking(bytes, logicalBitCount)

/** Creates exactly [nBits] unset mutable LSB0 bits. */
operator fun MutableLsb0BitArray.Companion.invoke(nBits: Long = 0): MutableLsb0BitArray =
    MutableBitArray(BitVector.BitOrder.LSB0, nBits) as MutableLsb0BitArray

/** Creates exactly [nBits] initialized mutable LSB0 bits. */
operator fun MutableLsb0BitArray.Companion.invoke(
    nBits: Int,
    initializer: (Int) -> Boolean,
): MutableLsb0BitArray = MutableBitArray(BitVector.BitOrder.LSB0, nBits, initializer) as MutableLsb0BitArray

/** Creates exactly [nBits] initialized mutable LSB0 bits. */
operator fun MutableLsb0BitArray.Companion.invoke(
    nBits: Long,
    initializer: (Long) -> Boolean,
): MutableLsb0BitArray = MutableBitArray(BitVector.BitOrder.LSB0, nBits, initializer) as MutableLsb0BitArray

/** Copies these bytes into a read-only fixed-size bit array using their declared native [bitOrder]. */
fun ByteArray.toBitArray(bitOrder: BitVector.BitOrder): BitArray = BitArray(bitOrder, this)

/** Copies these bytes into a mutable fixed-size bit array using their declared native [bitOrder]. */
fun ByteArray.toMutableBitArray(bitOrder: BitVector.BitOrder): MutableBitArray = MutableBitArray(bitOrder, this)

/**
 * Creates an independent [MutableBitArray] containing the same set logical indexes.
 */
fun UnboundedCompactingBitVector.toMutableBitArray(bitOrder: BitVector.BitOrder): MutableBitArray =
    MutableBitArray(bitOrder, highestSetIndex() + 1) { get(it) }

/**
 * Creates an independent [MutableBitArray] containing the same set logical indexes.
 */
fun UnboundedCompactingBitVector.toBitArray(bitOrder: BitVector.BitOrder): BitArray =
    BitArray(bitOrder, highestSetIndex() + 1) { get(it) }


private fun ByteArray.byteIterator(
    nativeOrder: BitVector.BitOrder,
    requestedOrder: BitVector.BitOrder,
    logicalBitCount: Long,
): ByteIterator =
    object : ByteIterator() {
        private var index = 0

        override fun hasNext(): Boolean = index < size

        override fun nextByte(): Byte {
            if (!hasNext()) throw NoSuchElementException()
            val byte = this@byteIterator[index].let {
                if (requestedOrder == nativeOrder) it else it.reverseBits()
            }
            return if (index++ == lastIndex) byte.maskUnusedBits(logicalBitCount, requestedOrder) else byte
        }
    }

private fun ByteArray.maskUnusedBits(logicalBitCount: Long, order: BitVector.BitOrder): ByteArray {
    if (isNotEmpty()) this[lastIndex] = this[lastIndex].maskUnusedBits(logicalBitCount, order)
    return this
}

private fun Byte.maskUnusedBits(logicalBitCount: Long, order: BitVector.BitOrder): Byte {
    val usedBits = (logicalBitCount % 8).toInt()
    if (usedBits == 0) return this
    val mask = when (order) {
        BitVector.BitOrder.LSB0 -> (1 shl usedBits) - 1
        BitVector.BitOrder.MSB0 -> 0xff shl (8 - usedBits)
    }
    return this and mask.toByte()
}
