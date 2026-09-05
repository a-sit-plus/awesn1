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
 *
 * ## Storage
 *
 * Bits are packed into a primitive [ByteArray]; there is no per-octet boxing, so a bit set costs about one byte per
 * eight bits rather than the four to eight bytes per octet a `MutableList<Byte>` reference array would need.
 *
 * Three quantities are deliberately kept apart:
 *
 * - **capacity** — the physical size of the backing array. It grows geometrically and is never shrunk by a write.
 * - **[inUse]** — an upper bound on the number of leading bytes that may contain a set bit. Every byte at or above it
 *   is guaranteed zero. It is raised in constant time by writes and lowered only by [normalizedByteLength].
 * - **length** — the exact compact extent, `[highestSetIndex] / 8 + 1`. It is computed lazily, by scanning down from
 *   [inUse] over zero bytes, and the result is memoised back into [inUse].
 *
 * Compactness is therefore a property of the *observable* representation rather than an invariant maintained on every
 * write: trailing zero bytes are never physically trimmed by [set]. This keeps writes O(1) amortised. Clearing a bit at
 * or above [inUse] changes nothing observable and is a pure no-op, so long runs of cleared bits cost nothing at all.
 *
 * Recomputing the length after the topmost byte has been cleared costs one downward scan over the zero bytes below it,
 * exactly as `java.util.BitSet.length()` does after its highest word is cleared. Repeatedly setting a far-away bit,
 * clearing it and then *observing* the set therefore stays linear in the gap, as it is on the JDK; the scan, not the
 * reallocation, is what that pattern costs. Writes on their own remain O(1): nothing scans until something reads.
 *
 * ## Releasing memory
 *
 * The backing array is shrunk only where the length is computed anyway — that is, at observation points such as
 * [highestSetIndex], [toLsb0ByteArray], the byte iterators, [equals] and the end of [mutateLsb0Bytes]. A set that has
 * collapsed to a fraction of its capacity therefore releases its storage the first time anything reads it. Use
 * [trimToSize] to release it immediately without an intervening read.
 *
 * Shrinking triggers at a quarter of capacity but targets twice the length. Because the trigger and the target differ
 * by a factor of two, a shrink can never be undone by the very next write: the set must double before it can trigger
 * growth again, and quarter before it can trigger another shrink.
 *
 * ## Thread safety
 *
 * This class is **not thread-safe** and carries no memory-visibility guarantees. Unlike the immutable ASN.1 elements,
 * whose `@Volatile` caches make them safe to share, a bit set is mutable throughout: writes reassign the backing array
 * when it grows, so concurrent use corrupts it outright and external synchronization is required to share an instance.
 *
 * The [ConcurrentModificationException] thrown by the byte iterators is best-effort detection of *sequential* misuse —
 * mutating while iterating, or retaining the [mutateLsb0Bytes] view past its scope — in the same spirit as the fail-fast
 * iterators of the Kotlin and Java collections. It is a way to surface bugs, never a concurrency guarantee, and must not
 * be relied upon for correctness.
 */
class BitSet private constructor(
    private var buffer: ByteArray,
    /** Upper bound on the number of leading bytes that may hold a set bit; every byte at or above this index is zero. */
    private var inUse: Int,
) : MutableUnboundedCompactingBitVector {

    /**
     * Bumped by every structural change, so stale byte iterators and [mutateLsb0Bytes] views fail loudly.
     *
     * Deliberately **not** `@Volatile`, matching `java.util.AbstractList.modCount`.
     */
    private var modCount: Int = 0

    /**
     * Mutates the compact backing bytes in place using LSB0 order. Byte zero holds logical indexes `0..7`, and logical
     * index zero uses mask `0x01`.
     *
     * The receiver is a live, growable view over the backing storage: its `size` is the compact byte length, and
     * `add`/`removeAt` grow and shrink this bit set. Growth goes through the same geometric reallocation the rest of the
     * class uses, so appending in a loop stays linear.
     *
     * The receiver must not be retained after [action] returns; every method on it throws [IllegalStateException]
     * afterwards. Trailing zero bytes are outside the view before and after the action, including when it throws, but
     * may exist transiently *within* it — for example after `add(0)` — and are dropped again on exit. Mutations made
     * before an exception remain applied.
     */
    @OptIn(ExperimentalContracts::class)
    @Throws(Throwable::class)
    fun mutateLsb0Bytes(action: MutableList<Byte>.() -> Unit) {
        contract { callsInPlace(action, InvocationKind.EXACTLY_ONCE) }
        normalize()
        val view = Lsb0ByteListView()
        try {
            view.action()
        } finally {
            view.invalidate()
            normalize()
        }
    }

    /**
     * Preallocates enough storage for [nBits] without changing this set's logical contents.
     *
     * @throws IllegalArgumentException if [nBits] is negative
     * @throws Asn1Exception if the required byte count cannot be represented
     */
    @Throws(IllegalArgumentException::class, Asn1Exception::class)
    constructor(nBits: Long = 0) : this(ByteArray(BitVector.getByteCount(nBits)), 0)

    /**
     * Returns the bit at [index], or `false` for any unset nonnegative index.
     *
     * Reading straight through the backing array is safe past [inUse] because every byte at or above it is zero.
     */
    override fun get(index: Long): Boolean = buffer.getLsb0Bit(index)

    /** Returns the first set bit at or after [fromIndex], or `-1`. */
    override fun nextSetBit(fromIndex: Long): Long {
        val length = normalizedByteLength()
        var byteIndex = BitVector.getByteIndexAsLong(fromIndex)
        // Only the first byte starts part-way in; every later one is scanned whole.
        var bitIndex = BitVector.getBitIndex(fromIndex)
        while (byteIndex < length) {
            val found = buffer[byteIndex.toInt()].nextSetLsb0BitIndex(bitIndex)
            if (found >= 0) return BitVector.getLogicalIndex(byteIndex, found)
            byteIndex++
            bitIndex = 0
        }
        return -1
    }

    /**
     * Sets or clears [index], growing the backing storage when necessary.
     *
     * Clearing a bit at or above [inUse] is a no-op: it is already clear, so no storage is touched and no compaction is
     * performed. Setting a bit grows capacity geometrically.
     */
    override fun set(index: Long, value: Boolean) {
        val byteIndex = BitVector.getByteIndex(index)
        val mask = BitVector.getLsb0Mask(index)
        if (!value) {
            if (byteIndex >= inUse) return
            buffer[byteIndex] = buffer[byteIndex] and mask.inv()
            modCount++
            return
        }
        if (byteIndex == Int.MAX_VALUE) throw Asn1Exception("BitSet byte count exceeds supported range")
        ensureCapacity(byteIndex + 1)
        buffer[byteIndex] = buffer[byteIndex] or mask
        if (byteIndex >= inUse) inUse = byteIndex + 1
        modCount++
    }

    /** Invokes [action] for logical indexes zero through [highestSetIndex]. */
    fun forEachIndexed(action: (index: Long, bit: Boolean) -> Unit) {
        for (index in 0..highestSetIndex()) action(index, get(index))
    }

    /** Returns compact Java `BitSet`-compatible LSB0 bytes. */
    override fun toLsb0ByteArray(): ByteArray = buffer.copyOf(normalizedByteLength())

    /** Returns compact MSB0 bytes*/
    override fun toMsb0ByteArray(): ByteArray =        ByteArray(normalizedByteLength()) { buffer[it].reverseBits() }

    /** Iterates compact Java `BitSet`-compatible LSB0 bytes without allocating a byte array. */
    override fun lsb0ByteIterator(): ByteIterator = byteIterator(reverseBits = false)

    /** Iterates compact MSB0 bytes without allocating a byte array. */
    override fun msb0ByteIterator(): ByteIterator = byteIterator(reverseBits = true)

    private fun byteIterator(reverseBits: Boolean): ByteIterator {
        val length = normalizedByteLength()
        val expectedModCount = modCount
        return object : ByteIterator() {
            private var index = 0

            override fun hasNext(): Boolean {
                if (modCount != expectedModCount) throw ConcurrentModificationException()
                return index < length
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
        val length = normalizedByteLength()
        if (length == 0) return -1
        return BitVector.getLogicalIndex((length - 1).toLong(), buffer[length - 1].highestSetLsb0BitIndex())
    }

    /**
     * Releases backing storage that the current contents do not need, without changing them.
     *
     * Observation points shrink on their own once capacity exceeds four times the compact length; call this to release
     * the memory immediately after a large set has been cleared and before anything reads it again.
     */
    fun trimToSize() {
        val length = normalizedByteLength()
        if (buffer.size > length) buffer = buffer.copyOf(length)
    }

    /**
     * Returns the exact compact byte length, lowering [inUse] to it and shrinking overlarge storage.
     *
     * Each byte scanned away lowers [inUse] permanently until a later [set] raises it again, so repeated calls are
     * amortised O(1) in the absence of intervening writes above the current length.
     */
    private fun normalizedByteLength(): Int {
        normalize()
        return inUse
    }

    /** [normalizedByteLength] without a result, for the call sites that only need the side effect. */
    private fun normalize() {
        var length = inUse
        while (length > 0 && buffer[length - 1] == ZERO) length--
        if (length != inUse) inUse = length
        maybeShrink(length)
    }

    /**
     * Shrinks to twice the length once capacity reaches four times it. The gap between the trigger (a quarter) and the
     * target (a half) means a shrink cannot be undone by the very next write.
     */
    private fun maybeShrink(length: Int) {
        if (buffer.size <= MIN_CAPACITY) return
        if (length.toLong() * 4 > buffer.size) return
        val target = maxOf(length.toLong() * 2, MIN_CAPACITY.toLong()).toInt()
        if (target < buffer.size) buffer = buffer.copyOf(target)
    }

    private fun ensureCapacity(byteCount: Int) {
        if (byteCount <= buffer.size) return
        val doubled = if (buffer.size > Int.MAX_VALUE / 2) Int.MAX_VALUE else buffer.size * 2
        buffer = buffer.copyOf(maxOf(byteCount, maxOf(doubled, MIN_CAPACITY)))
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is BitSet) return false
        val length = normalizedByteLength()
        if (length != other.normalizedByteLength()) return false
        for (index in 0 until length) if (buffer[index] != other.buffer[index]) return false
        return true
    }

    override fun hashCode(): Int {
        var result = 1
        for (index in 0 until normalizedByteLength()) result = 31 * result + buffer[index]
        return result
    }

    /**
     * Growable `MutableList<Byte>` view over the backing bytes, handed to [mutateLsb0Bytes].
     *
     * Its `size` is [inUse], which [mutateLsb0Bytes] normalises to the exact compact length before the view is created.
     * Writes go straight through to the backing array; nothing is copied.
     */
    private inner class Lsb0ByteListView : AbstractMutableList<Byte>() {
        private var valid = true

        fun invalidate() {
            valid = false
        }

        private fun checkValid() =
            check(valid) { "This MutableList view must not be retained after mutateLsb0Bytes returns" }

        override val size: Int
            get() {
                checkValid()
                return inUse
            }

        override fun get(index: Int): Byte {
            checkValid()
            checkElementIndex(index)
            return buffer[index]
        }

        override fun set(index: Int, element: Byte): Byte {
            checkValid()
            checkElementIndex(index)
            return buffer[index].also {
                buffer[index] = element
                modCount++
            }
        }

        override fun add(index: Int, element: Byte) {
            checkValid()
            if (index !in 0..inUse) throw IndexOutOfBoundsException("index = $index, size = $inUse")
            if (inUse == Int.MAX_VALUE) throw Asn1Exception("BitSet byte count exceeds supported range")
            ensureCapacity(inUse + 1)
            buffer.copyInto(buffer, index + 1, index, inUse)
            buffer[index] = element
            inUse++
            modCount++
        }

        override fun removeAt(index: Int): Byte {
            checkValid()
            checkElementIndex(index)
            val removed = buffer[index]
            buffer.copyInto(buffer, index, index + 1, inUse)
            // Preserve the invariant that every byte at or above inUse is zero.
            buffer[inUse - 1] = ZERO
            inUse--
            modCount++
            return removed
        }

        private fun checkElementIndex(index: Int) {
            if (index !in 0 until inUse) throw IndexOutOfBoundsException("index = $index, size = $inUse")
        }
    }

    companion object {
        private const val ZERO: Byte = 0

        /** Smallest backing array this set will shrink to; avoids churn on tiny sets. */
        private const val MIN_CAPACITY = 8

        /** Creates a set from [nBits] initializer values; trailing false values do not define a size. */
        operator fun invoke(nBits: Int, initializer: (Int) -> Boolean): BitSet = BitSet(nBits.toLong()).apply {
            for (index in 0 until nBits) if (initializer(index)) set(index)
        }

        operator fun invoke(vararg bits: Boolean): BitSet = invoke(bits.size) { bits[it] }

        /** Copies Java `BitSet`-compatible LSB0 [bytes] into a new bit set. */
        operator fun invoke(bytes: ByteArray): BitSet = BitSet(bytes.copyOf(), bytes.size)

        //to call private ctor from FixedSizeBitVector.toBitSet()
        internal fun adopt(bytes: ByteArray): BitSet = BitSet(bytes, bytes.size)

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
 * intentionally loses trailing unset bits and the exact [FixedSizeBitVector.logicalBitCount].
 *
 * The bits are transferred in bulk through [FixedSizeBitVector.toLsb0ByteArray] rather than one index at a time, so the
 * cost is one array copy rather than one call per bit.
 */
fun FixedSizeBitVector.toBitSet(): BitSet = BitSet.adopt(toLsb0ByteArray())


/**
 * Creates an independent [BitSet] containing the same set logical indexes. As [BitSet] is unbounded, this conversion
 * intentionally loses trailing unset bits and the exact [FixedSizeBitVector.logicalBitCount].
 */
fun FixedSizeBitVector.toUnboundedCompactingBitVector(): UnboundedCompactingBitVector = toBitSet()
