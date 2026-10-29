// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlin.experimental.and
import kotlin.experimental.inv
import kotlin.experimental.or

private fun getByteIndex(i: Long) : Int {
    if (i < 0) throw IndexOutOfBoundsException("index = $i")
    return (i / 8).toNonnegativeIntChecked("BitSet byte index").also {
        if (it == Int.MAX_VALUE) throw IndexOutOfBoundsException("index = $i")
    }
}

private fun List<Byte>.getBit(index: Long): Boolean {
    if (index < 0) throw IndexOutOfBoundsException("index = $index")
    val byteIndex = index/8
    if (byteIndex >= size) return false
    val byte = this[byteIndex.toInt()]
    return (byte and getBitMask(index)) != 0.toByte()
}

private fun getBitMask(index: Long) =
    (1 shl (index.toInt() and 7)).toByte()

/**
 * Pure Kotlin Bit Set created by throwing a bunch of extension functions at a `MutableList<Byte>`.
 * As a mental model: this BitSet grows from left to right, just like writing a text.
 *
 * **Note:** The in-byte bit index vs. the global index (for iterating over the bytes contained in the list) run in opposing directions!
 *
 * The [toBitStringView] function print our the bits as they are accessible, disregarding byte-alignment and memory layout:
 *
 * ```kotlin
 * val bitSet = BitSet()
 * bitSet[0] = true //1             (ByteArray representation: [1])
 * bitSet[2] = true //101           (ByteArray representation: [5])
 * bitSet[8] = true //10100000 1    (ByteArray representation: [5,1])
 * ```
 *
 * To inspect the actual memory layout of the underlying bytes (i.e. the result of calling [toByteArray]), use [memDumpView].
 *
 * Implements [Iterable] over bits. Use [bytes] to iterate over bytes
 */
@Serializable(with = BitSetSerializer::class)
class BitSet private constructor(private val buffer: ArrayList<Byte>) : Iterable<Boolean> {

    /** Creates a deep copy of the current `BitSet` instance.
     * @return A new `BitSet` object containing the same state as the current one. */
    fun copyOf(): BitSet = BitSet(ArrayList(buffer))

    /** List view on the bytes backing this bit set. */
    val bytes: List<Byte> = object : AbstractList<Byte>() {
        override val size: Int get() = buffer.size
        override fun get(index: Int): Byte = buffer[index]
    }

    /** Preallocates a buffer capable of holding [nBits] many bits */
    constructor(nBits: Long = 0) : this(
        ArrayList(getByteIndex(nBits) + if (nBits % 8 == 0L) 0 else 1)
    )

    /**
     * Returns the bit at [index]. Never throws an exception when [index]>=0, as getting a bit outside the underlying
     * bytes' bounds returns false.
     */
    operator fun get(index: Long): Boolean = buffer.getBit(index)
    operator fun get(index: Int): Boolean = this[index.toLong()]

    /**
     * Returns the first bit set to true from [fromIndex] *(= inclusive)*.
     * @return the index of the first bit set to true, or -1 if there are no bits set to true
     */
    fun nextSetBit(fromIndex: Long): Long {
        if (fromIndex < 0) throw IndexOutOfBoundsException("fromIndex = $fromIndex")
        if ((fromIndex / 8) >= buffer.size) return -1

        var index = fromIndex
        while ((index%8) != 0L) {
            if (this[index]) return index
            index++
        }

        for (i in getByteIndex(index) until buffer.size) {
            val byte = buffer[i]
            if (byte == 0.toByte()) continue
            return i * 8L + byte.countTrailingZeroBits()
        }
        return -1
    }

    /**
     * Returns the first bit set to true *after* [index] (= exclusive).
     * @return the index of the first bit set to true, or -1 if there are no bits set to true
     */
    fun nextSetBitAfter(index: Long): Long = if (index == Long.MAX_VALUE) -1 else nextSetBit(index+1)

    /** Using this is not required, but doing so before invoking [internalSet] is more efficient */
    private fun ensureCapacityForIndex(bitIndex: Long) {
        val requiredIndex = getByteIndex(bitIndex)
        if (requiredIndex >= buffer.size)
        buffer.ensureCapacity(requiredIndex + 1)
    }

    /** does not compact the set; caller needs to ensure that if internalSet was called with a `false` [value],
     * that the list is [compact]ed afterwards */
    private fun internalSet(index: Long, value: Boolean) {
        val byteIndex = getByteIndex(index)
        if (value) {
            while (buffer.size <= byteIndex) buffer.add(0)
            buffer[byteIndex] = buffer[byteIndex] or getBitMask(index)
        } else {
            if (buffer.size <= byteIndex) return
            buffer[byteIndex] = buffer[byteIndex] and getBitMask(index).inv()
        }
    }
    /** Sets the bit at [index] to [value] */
    operator fun set(index: Long, value: Boolean) {
        if (value) ensureCapacityForIndex(index)
        internalSet(index, value)
        if (!value) compact()
    }
    /** Sets the bit at [index] to [value] */
    operator fun set(index: Int, value: Boolean) = set(index.toLong(), value)
    /** Sets the bits in [indexes] to [value] */
    operator fun set(indexes: LongRange, value: Boolean) {
        if (indexes.isEmpty()) return
        if (value) ensureCapacityForIndex(indexes.last)
        indexes.forEach { internalSet(it, value) }
        if (!value) compact()
    }
    operator fun set(indexes: IntRange, value: Boolean) = set(indexes.toLongRange(), value)

    fun flip(index: Long) { this[index] = !this[index] }
    fun flip(indexes: LongRange) {
        if (indexes.isEmpty()) return
        ensureCapacityForIndex(indexes.last)
        indexes.forEach { internalSet(it, !get(it)) }
        compact()
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
    inline fun forEachIndexed(action: (i: Long, it: Boolean) -> Unit) {
        for (i in 0..highestSetIndex()) action(i, this[i])
    }

    /**
     * Allocates a fresh byte array and writes the values of this bitset's underlying bytes to it.
     * Within each byte, index 0 is the least significant bit, while index 7 is the most significant bit.
     * (This matches Java's `java.util.BitSet::toByteArray`.)
     */
    fun toByteArray(): ByteArray = buffer.toByteArray()

    /**
     * Re-allocates the internal buffer to not consume any memory beyond what is necessary to store the bits.
     * This trims any spare capacity, and should only be used if the `BitSet` is not expected to grow further, and
     * memory is a concern. If the set might grow again, this is almost certainly not worth it. */
    fun trimToSize() { buffer.trimToSize() }

    private fun compact() {
        for (i in buffer.indices.reversed()) {
            if (buffer[i] == 0.toByte()) buffer.removeAt(i) else return
        }
    }

    val indices: LongRange get() = (0L..highestSetIndex())

    fun highestSetIndex() =
        if (buffer.isEmpty()) -1
        else (buffer.size * 8L) - buffer.last().countLeadingZeroBits() - 1

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
    fun toBitStringView() = buffer.joinToString(separator = "") {
        it.toUByte().toString(2).padStart(8, '0').reversed()
    }.dropLastWhile { it == '0' }

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
    fun memDumpView() = buffer.joinToString(separator = " ") { it.toUByte().toString(2).padStart(8, '0') }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is BitSet) return false
        return (buffer == other.buffer)
    }

    override fun hashCode(): Int = buffer.hashCode()


    /**
     * returns an iterator over bits. use [bytes]`.iterator()` to iterate over bytes. modifying the [BitSet] invalidates the iterator, causing undefined behavior.
     */
    override fun iterator(): Iterator<Boolean> = object : Iterator<Boolean> {
        var index = 0L
        val max = highestSetIndex()
        override fun hasNext(): Boolean = index <= max
        override fun next(): Boolean = if (hasNext()) get(index++) else throw NoSuchElementException()
    }

    companion object {

        @Suppress("INVISIBLE_MEMBER", "INVISIBLE_REFERENCE")
        @kotlin.internal.LowPriorityInOverloadResolution
        // marking this one as low priority because the Int one is older; it will still be selected if you explicitly pass a Long
        operator fun invoke(nBits: Long, initializer: (Long) -> Boolean): BitSet =
            BitSet(nBits).apply {
                (0 until nBits).forEach {
                    if (initializer(it)) set(it)
                }
            }

        operator fun invoke(nBits: Int, initializer: (Int) -> Boolean) = invoke(nBits.toLong()) { initializer(it.toInt()) }

        operator fun invoke(vararg bits: Boolean) =
            invoke(bits.size) { bits[it] }

        /**
         * Wraps [bytes] into a BitSet. Copies all bytes.
         * Hence, modifications to [bytes] are **not** reflected in the newly created BitSet.
         */
        operator fun invoke(bytes: ByteArray) =
            BitSet(bytes.toCollection(ArrayList(bytes.size)))
                .also(BitSet::compact)

        /**
         * Creates bitset from hunan-readably bit string representation
         * @throws IllegalArgumentException if the provided string contains characters other than '1' and '0'
         */
        @Throws(IllegalArgumentException::class)
        fun fromString(stringRepresentation: String): BitSet {
            if (stringRepresentation.isEmpty()) return BitSet()
            if (!stringRepresentation.matches(Regex("^[01]+\$"))) throw IllegalArgumentException("Not a bit string")
            return BitSet(stringRepresentation.length.toLong()).apply {
                stringRepresentation.forEachIndexed { i, it ->
                    this[i.toLong()] = (it == '1')
                }
            }
        }

        /**
         * Exception-free version of [fromString]
         */
        fun fromBitStringOrNull(bitString: String) = catchingUnwrapped { fromString(bitString) }.getOrNull()
    }
}

/** sets the bit at [index] (shorthand for `this[index] = true`) */
fun BitSet.set(index: Long) { this[index] = true }
/** sets the bit at [index] (short-hand for `this[index] = true`) */
fun BitSet.set(index: Int) = set(index.toLong())
/** sets the bits in [indexes] (shorthand for `this[indexes] = true`) */
fun BitSet.set(indexes: LongRange) { this[indexes] = true }
/** sets all bits from [fromIndex] (inclusive) to [toIndex] (exclusive) */
fun BitSet.set(fromIndex: Long, toIndex: Long) = set(fromIndex until toIndex)

/** clears the bit at [index] (shorthand for `this[index] = false`) */
fun BitSet.clear(index: Long) { this[index] = false }
/** clears the bit at [index] (shorthand for `this[index] = false`) */
fun BitSet.clear(index: Int) = clear(index.toLong())
/** clears the bits in [indexes] (shorthand for `this[indexes] = false`) */
fun BitSet.clear(indexes: LongRange) { this[indexes] = false }
/** clears all bits from [fromIndex] (inclusive) to [toIndex] (exclusive) */
fun BitSet.clear(fromIndex: Long, toIndex: Long) = clear(fromIndex until toIndex)

fun BitSet.flip(index: Int) = flip(index.toLong())
fun BitSet.flip(fromIndex: Long, toIndex: Long) = flip(fromIndex until toIndex)

private fun IntRange.toLongRange() = LongRange(start.toLong(), endInclusive.toLong())

/**
 * Serializer for [BitSet], behaving the same as serializing an [Asn1BitString]
 */
object BitSetSerializer : KSerializer<BitSet> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("at.asitplus.awesn1.BitSet", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): BitSet =
        decoder.decodeSerializableValue(Asn1BitString.serializer()).toBitSet()

    override fun serialize(encoder: Encoder, value: BitSet) =
        encoder.encodeSerializableValue(Asn1BitString.serializer(), Asn1BitString(value))

}
