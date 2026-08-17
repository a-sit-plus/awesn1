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

private fun getByteIndex(i: Long) = (i / 8).toNonnegativeIntChecked("BitSet byte index")
private fun getBitIndex(i: Long) = (i % 8).toInt()

private fun List<Byte>.getBit(index: Long): Boolean {
    if (index < 0) throw IndexOutOfBoundsException("index = $index")
    val byteIndex = index / 8
    if (byteIndex >= size) return false
    return this[byteIndex.toInt()].getBit(getBitIndex(index))
}

private fun Byte.getBit(index: Int): Boolean =
    if (index !in 0..7) throw IndexOutOfBoundsException("bit index $index out of bounds.")
    else (((1 shl index).toByte() and this) != 0.toByte())

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
class BitSet private constructor(private val buffer: MutableList<Byte>) : Iterable<Boolean> {


    /**
     * Creates a deep copy of the current `BitSet` instance.
     *
     * @return A new `BitSet` object containing the same state as the current one.
     */
    fun copyOf(): BitSet = BitSet(bytes.toMutableList())

    /**
     * List view on the bytes backing this bit set. Changes to the bytes directly affect this bitset.
     */
    val bytes: List<Byte> get() {
        compact()
        return buffer
    }

    /**
     * Preallocates a buffer capable of holding [nBits] many bits
     */
    constructor(nBits: Long = 0) : this(
        if (nBits < 0) throw IllegalArgumentException("a bit set of size $nBits makes no sense")
        else MutableList((getByteIndex(nBits).toLong() + 1).toNonnegativeIntChecked("BitSet preallocate size")) { 0.toByte() })

    /**
     * Returns the bit at [index]. Never throws an exception when [index]>=0, as getting a bit outside the underlying
     * bytes' bounds returns false.
     */
    operator fun get(index: Long): Boolean = buffer.getBit(index)

    /**
     * Returns the first bit set to true from [fromIndex] *(= inclusive)*.
     * @return the index of the first bit set to true, or -1 if there are no bits set to true
     */
    fun nextSetBit(fromIndex: Long): Long {
        if (fromIndex < 0) throw IndexOutOfBoundsException("fromIndex = $fromIndex")
        val byteIndex = getByteIndex(fromIndex)
        val compactBytes = bytes
        if (byteIndex >= compactBytes.size) return -1
        else {
            compactBytes.subList(byteIndex, compactBytes.size).let { list ->
                val startIndex = getBitIndex(fromIndex).toLong()
                for (i: Long in startIndex until list.size.toLong() * 8L) {
                    if (list.getBit(i)) return byteIndex.toLong() * 8L + i
                }
            }
            return -1
        }
    }

    /**
     * Returns the first bit set to true *after* [index] (= exclusive).
     * @return the index of the first bit set to true, or -1 if there are no bits set to true
     */
    fun nextSetBitAfter(index: Long):Long = nextSetBit(index+1)

    /**
     * Sets the bit at [index] to [value]
     */
    operator fun set(index: Long, value: Boolean) {
        val byteIndex = getByteIndex(index)
        while (buffer.size <= byteIndex) buffer.add(0)
        val byte = buffer[byteIndex]
        buffer[byteIndex] =
            if (value) {
                ((1 shl getBitIndex(index)).toByte() or byte)
            } else
                ((1 shl getBitIndex(index)).toByte().inv() and byte)
        if (!value) compact()
    }

    /**
     * Current length of the bitset.
     */
    fun length(): Long = highestSetIndex() + 1L

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
        for (i in 0..<length()) action(i, this[i])
    }

    /**
     * Allocates a fresh byte array and writes the values of this bitset's underlying bytes to it
     */
    fun toByteArray(): ByteArray {
        return if (buffer.isEmpty() || highestSetIndex() == -1L) byteArrayOf()
        else buffer.subList(0, getByteIndex(highestSetIndex()) + 1).toTypedArray().toByteArray()
    }

    private fun compact() {
        for (i in buffer.indices.reversed()) {
            if (buffer[i] == 0.toByte()) buffer.removeAt(i) else return
        }
    }

    private fun highestSetIndex(): Long {
        compact()
        for (i: Long in buffer.size.toLong() * 8L - 1L downTo 0L) {
            if (buffer.getBit(i)) return i
        }
        return -1L
    }

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
     * ````
     */
    fun memDumpView() = toByteArray().memDumpView()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is BitSet) return false
        return toByteArray().contentEquals(other.toByteArray())
    }

    override fun hashCode(): Int = toByteArray().contentHashCode()


    /**
     * returns an iterator over bits. use [bytes]`.iterator()` to iterate over bytes
     */
    override fun iterator(): Iterator<Boolean> = object : Iterator<Boolean> {
        var index = 0L
        override fun hasNext(): Boolean = index < length()
        override fun next(): Boolean = get(index++)
    }

    companion object {

        //yes, int, because if you want more, init using a bytearray!
        operator fun invoke(nBits: Int, initializer: (Int) -> Boolean): BitSet = BitSet(nBits.toLong()).apply {
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
        operator fun invoke(bytes: ByteArray) = BitSet(bytes.toMutableList())

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

/**
 * copies this byteArray into a [BitSet]
 */
fun ByteArray.toBitSet(): BitSet = BitSet(this)


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
 * │      0  0  0  0  1  1  0  1       │
 * │   ◄─23─22─21─20─19─18─17─16─┐  │
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
 * ````
 */
fun ByteArray.memDumpView(): String =
    joinToString(separator = " ") { it.toUByte().toString(2).padStart(8, '0') }

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

/**
 * shorthand for `set(index, true)`
 */
fun BitSet.set(index: Long) {
    this[index] = true
}

fun BitSet.set(index: Int) = set(index.toLong())


operator fun BitSet.get(index: Int): Boolean = this[index.toLong()]
operator fun BitSet.set(index: Int, value: Boolean) {
    this[index.toLong()] = value
}

fun BitSet.flip(index: Long) {
    this[index] = !this[index]
}

fun BitSet.flip(index: Int) = flip(index.toLong())

/**
 * shorthand for `set(index, false)`
 */
fun BitSet.clear(index: Long) {
    this[index] = false
}

fun BitSet.clear(index: Int) = clear(index.toLong())

fun BitSet.flip(fromIndex: Long, toIndex: Long) = flip(LongRange(fromIndex, toIndex))
fun BitSet.flip(indexes: LongRange) = indexes.forEach { flip(it) }
fun BitSet.set(fromIndex: Long, toIndex: Long) = set(LongRange(fromIndex, toIndex))
fun BitSet.set(indexes: LongRange) = indexes.forEach { set(it) }
fun BitSet.clear(fromIndex: Long, toIndex: Long) = clear(LongRange(fromIndex, toIndex))
fun BitSet.clear(longRange: LongRange) = longRange.forEach { clear(it) }
