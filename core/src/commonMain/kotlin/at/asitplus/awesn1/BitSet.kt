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
 * Implements [Iterable] over bits. Use [mutableBytes] to iterate over bytes
 */
class BitSet private constructor(private val buffer: MutableList<Byte>) : MutableBitVector {


    /**
     * Creates a deep copy of the current `BitSet` instance.
     *
     * @return A new `BitSet` object containing the same state as the current one.
     */
    override fun copyOf(): BitSet = BitSet(mutableBytes.toMutableList())
    override val byteIterator: ByteIterator
        get() = object : ByteIterator() {
            var index = 0
            val initialSize = mutableBytes.size
            override fun nextByte(): Byte {
                if (initialSize != mutableBytes.size) throw ConcurrentModificationException()
                return buffer[index++]
            }

            override fun hasNext(): Boolean {
                if (initialSize != mutableBytes.size) throw ConcurrentModificationException()
                return index < initialSize - 1
            }
        }

    /**
     * List view on the bytes backing this bit set. Changes to the bytes directly affect this bitset.
     */
    val mutableBytes: MutableList<Byte>
        get() {
            compact()
            return buffer
        }

    /**
     * Preallocates a buffer capable of holding [nBits] many bits
     */
    constructor(nBits: Long = 0) : this(
        if (nBits < 0) throw IllegalArgumentException("a bit set of size $nBits makes no sense")
        else with(BitVector.Companion){MutableList((getByteIndex(nBits).toLong() + 1).toNonnegativeIntChecked("BitSet preallocate size")) { 0.toByte() }})

    /**
     * Returns the bit at [index]. Never throws an exception when [index]>=0, as getting a bit outside the underlying
     * bytes' bounds returns false.
     */
    override operator fun get(index: Long): Boolean = buffer.getBit(index)

    /**
     * Returns the first bit set to true from [fromIndex] *(= inclusive)*.
     * @return the index of the first bit set to true, or -1 if there are no bits set to true
     */
    override fun nextSetBit(fromIndex: Long): Long {
        if (fromIndex < 0) throw IndexOutOfBoundsException("fromIndex = $fromIndex")
        val byteIndex =  with(BitVector.Companion){getByteIndex(fromIndex)}
        val compactBytes = mutableBytes
        if (byteIndex >= compactBytes.size) return -1
        else {
            compactBytes.subList(byteIndex, compactBytes.size).let { list ->
                val startIndex =  with(BitVector.Companion){getBitIndex(fromIndex).toLong()}
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
    override fun nextSetBitAfter(index: Long): Long = nextSetBit(index + 1)

    /**
     * Sets the bit at [index] to [value]
     */
    override operator fun set(index: Long, value: Boolean) {
        with(BitVector.Companion) {
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
    override fun toByteArray(): ByteArray = with(BitVector.Companion){
        return if (mutableBytes.isEmpty()) byteArrayOf()
        else buffer.subList(0, getByteIndex(highestSetIndex()) + 1).toTypedArray().toByteArray()
    }

    private fun compact() {
        for (i in buffer.indices.reversed()) {
            if (buffer[i] == 0.toByte()) buffer.removeAt(i) else return
        }
    }

    override fun highestSetIndex(): Long {
        for (i: Long in mutableBytes.size.toLong() * 8L - 1L downTo 0L) {
            if (buffer.getBit(i)) return i
        }
        return -1L
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is BitSet) return false
        return toByteArray().contentEquals(other.toByteArray())
    }

    override fun hashCode(): Int = toByteArray().contentHashCode()


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
fun ByteArray.toBitSet(): BitSet = BitSet(this)

/**
 * Serializer for [BitSet], behaving the same as serializing an [Asn1BitString]
 */
object BitSetSerializer : KSerializer<BitSet> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("at.asitplus.awesn1.BitSet", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): BitSet =
        decoder.decodeSerializableValue(Asn1BitString.serializer()).toBitSet()

    override fun serialize(encoder: Encoder, value: BitSet) =
        encoder.encodeSerializableValue(Asn1BitString.serializer(), Asn1BitString(value))

}
