// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(at.asitplus.awesn1.InternalAwesn1Api::class, ExperimentalUnsignedTypes::class)

package at.asitplus.awesn1

import at.asitplus.awesn1.Asn1Integer.Companion.fromTwosComplement
import at.asitplus.awesn1.encoding.*
import at.asitplus.awesn1.encoding.internal.*
import at.asitplus.awesn1.serialization.Asn1Serializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlin.experimental.or
import kotlin.jvm.JvmInline

private val REGEX_BASE10 = Regex("[0-9]+")
private val REGEX_ZERO = Regex("0*")

fun Asn1Integer(number: Int) = Asn1Integer(number.toLong())
fun Asn1Integer(number: Long) =
    if (number < 0) Asn1Integer.Negative(VarUInt((number * -1).toULong()))
    else Asn1Integer.Positive(VarUInt((number).toULong()))

fun Asn1Integer(number: UInt) = Asn1Integer(number.toULong())
fun Asn1Integer(number: ULong) =
    Asn1Integer.Positive(VarUInt(number))

/**
 * A very simple implementation of an ASN.1 variable-length integer.
 * It is only good for reading from and writing to ASN.1 structures. It is not a BigInt, nor does it define any operations.
 * It has a [sign] though, and supports [twosComplement] representation and converting [fromTwosComplement].
 * Hence, it directly interoperates with [Kotlin MP BigNum](https://github.com/ionspin/kotlin-multiplatform-bignum) and the JVM BigInteger.
 */
@Serializable(with = Asn1Integer.Companion::class)
sealed class Asn1Integer(internal val uint: VarUInt, val sign: Sign) : Asn1Encodable<Asn1Primitive> {

    override fun encodeToTlv(): Asn1Primitive = encodeToAsn1Primitive()

    enum class Sign {
        POSITIVE,
        NEGATIVE
    }

    override fun toString(): String = when (sign) {
        Sign.POSITIVE -> uint.toString()
        Sign.NEGATIVE -> "-${uint}"
    }

    /** Encodes the [Asn1Integer] to its minimum-size twos-complement encoding. Non-empty. */
    abstract fun twosComplement(): ByteArray

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Asn1Integer) return false

        if (sign != other.sign) return false
        return (uint.isEqualTo(other.uint))
    }

    override fun hashCode(): Int {
        var result = uint.words.contentHashCode()
        result = 31 * result + sign.hashCode()
        return result
    }

    fun isZero() = uint.isZero()

    /** The minimum-size unsigned bytearray encoding of this number's absolute value. Non-empty. */
    val magnitude by lazy { uint.bytes.asByteArray() }

    @Serializable(with = Asn1IntegerPositiveSerializer::class)
    class Positive internal constructor(uint: VarUInt) : Asn1Integer(uint, Sign.POSITIVE) {
        override fun twosComplement(): ByteArray = uint.bytes.let {
            if (it.first().countLeadingZeroBits() == 0) listOf(0.toUByte()) + it else it
        }.toUByteArray().asByteArray()

        /** The number of bits required to represent this value */
        fun bitLength() = uint.bitLength().toUInt()

    }

    @Serializable(with = Asn1IntegerNegativeSerializer::class)
    class Negative internal constructor(uint: VarUInt) : Asn1Integer(uint, Sign.NEGATIVE) {
        init {
            check(!uint.isZero()) // there is no negative zero
        }

        override fun twosComplement(): ByteArray {
            if (uint == VarUInt(1u)) return byteArrayOf(-1)
            return uint.bytes.twosComplementNegativeBytes().asByteArray()
        }
    }

    companion object : Asn1Serializer<Asn1Primitive, Asn1Integer>(
        leadingTags = setOf(Asn1Element.Tag.INT),
        decodable = object : Asn1Decodable<Asn1Primitive, Asn1Integer> {
            override fun doDecode(src: Asn1Primitive): Asn1Integer = src.decodeToAsn1Integer(src.tag)
        },
        fallbackSerializer = Asn1IntegerStringSerializer,
    ) {
        override val descriptor: SerialDescriptor =
            PrimitiveSerialDescriptor(ASN1_DESCRIPTOR_INTEGER, PrimitiveKind.STRING)

        val ONE  by lazy { Asn1Integer.Positive(VarUInt(1u)) }
        val ZERO by lazy { Asn1Integer.Positive(VarUInt(0u)) }

        /** Constructs an [Asn1Integer] from a decimal string */
        fun fromDecimalString(input: String): Asn1Integer {
            require(input.isNotEmpty())
            val (numericPart, sign) = when {
                input.first() == '-' -> Pair(input.substring(1), Sign.NEGATIVE)
                else -> Pair(input, Sign.POSITIVE)
            }
            require(numericPart.matches(REGEX_BASE10)) { "NaN: $input" }
            return fromSignMagnitude(VarUInt(numericPart), sign)
        }

        private fun fromSignMagnitude(magnitude: VarUInt, sign: Sign) = when {
            sign == Sign.POSITIVE || magnitude.isZero() -> Positive(magnitude)
            else -> Negative(magnitude)
        }

        /** Constructs an [Asn1Integer] from its sign-magnitude representation */
        fun fromByteArray(magnitude: ByteArray, sign: Sign) =
            fromSignMagnitude(VarUInt(magnitude), sign)

        /** Constructs a non-negative [Asn1Integer] from its unsigned magnitude representation */
        fun fromUnsignedByteArray(magnitude: ByteArray) = Positive(VarUInt(magnitude))

        /** Constructs an [Asn1Integer] from its twos-complement byte representation
         *
         * @param lenient Relaxes DER constraints, which are:
         * - The content of the `INTEGER` type is not empty.
         * - The `INTEGER` value is minimally encoded, verifying that:
         *     - Positive ints do not contain leading zero bytes unless necessary.
         *     - Negative ints do not use excessive sign extension bytes.
         */
        fun fromTwosComplement(input: ByteArray, lenient: Boolean = false): Asn1Integer {
            if (!lenient) input.validateDerConstraints()
            return when {
                input.isEmpty() -> Positive(VarUInt())
                (input.first() < 0) ->
                    Negative(VarUInt(input.asUByteArray().decodeNegativeMagnitude()))

                else -> Positive(VarUInt(input))
            }
        }

        private fun ByteArray.validateDerConstraints() =
            runRethrowing { throughBuffer { it.validateDerIntConstraints() } }
    }
}

private fun UByteArray.twosComplementNegativeBytes(): UByteArray {
    // Negate at the magnitude's own byte width. Routing through VarUInt.inv()+1 (as decodeNegativeMagnitude
    // does) trims any high bytes that invert to 0x00 — i.e. magnitude bytes equal to 0xFF — which drops the
    // leading sign-extension bytes and corrupts the encoding of large negative values.
    val result = UByteArray(size)
    var carry = 1u
    for (i in size - 1 downTo 0) {
        val sum = (this[i].inv()) + carry.toUByte()
        result[i] = (sum).toUByte()
        carry = sum shr 8
    }
    // A leading byte whose top bit is clear would be misread as a positive INTEGER; prepend 0xFF.
    if (result.first().toByte() < 0) return result
    return UByteArray(size + 1) { index ->
        if (index == 0) 0xFFu else result[index - 1]
    }
}

private fun UByteArray.decodeNegativeMagnitude(): UByteArray {
    return (VarUInt(this).inv() + 1.toUByte()).bytes
}

/**
 * The integer must fit the valid Int value range (within Int.MIN_VALUE..Int.MAX_VALUE), otherwise a [NumberFormatException] will be thrown.
 */
@Throws(NumberFormatException::class)
fun Asn1Integer.toInt(): Int = toString().toInt()
fun Asn1Integer.toIntOrNull(): Int? = toString().toIntOrNull()

// ?????????????????????????????????????????????????????????????????????????????????????????????
// ??? WHY DOES THIS NOT EXIST IN THE STANDARD LIBRARY ????? ????? ????? ????? ????? ????? ?????
// ?????????????????????????????????????????????????????????????????????????????????????????????
@Suppress("NOTHING_TO_INLINE")
private inline infix fun UByte.shr(bitCount: Int) =
    (toUInt() shr bitCount).toUByte()

@Suppress("NOTHING_TO_INLINE")
private inline infix fun UByte.shl(bitCount: Int) =
    (toUInt() shl bitCount).toUByte()

@Suppress("NOTHING_TO_INLINE")
private inline fun combine(highByte: UByte, lowByte: UByte, highBits: Int) =
    ((highByte.toUInt() shl (8 - highBits)) or (lowByte.toUInt() shr highBits)).toUByte()


@JvmInline
internal value class VarUInt private constructor(val words: UByteArray) {

    init {
        check(!words.isEmpty())
        check((words.size == 1) || (words.first() != 0x00u.toUByte()))
    }

    @Suppress("NOTHING_TO_INLINE")
    inline fun isEqualTo(other: VarUInt) = (words contentEquals other.words)

    val bytes get() = words.copyOf()

    override fun toString() = words.iterator().toDecimalString()
    fun toHexString() = StringBuilder().apply {
        words.forEachIndexed { i, it ->
            append(
                it.toString(16).run { if (i > 0 && length < 2) "0$this" else this })
        }
    }.toString()

    infix fun and(other: VarUInt): VarUInt {
        val (shorter, longer) = if (other.words.size < words.size) other to this else this to other
        val diff = longer.words.size - shorter.words.size
        return constructFromUntrimmed(UByteArray(shorter.words.size) {
            shorter.words[it] and longer.words[it + diff]
        }, isOwned = true)
    }

    infix fun or(other: VarUInt): VarUInt {
        val (shorter, longer) = if (other.words.size < words.size) other to this else this to other
        val diff = longer.words.size - shorter.words.size
        return VarUInt(UByteArray(longer.words.size) {
            if (it >= diff) shorter.words[it - diff] or longer.words[it]
            else longer.words[it]
        })
    }

    infix fun xor(other: VarUInt): VarUInt {
        val (shorter, longer) = if (other.words.size < words.size) other to this else this to other
        val diff = longer.words.size - shorter.words.size
        return constructFromUntrimmed(UByteArray(longer.words.size) {
            if (it >= diff) shorter.words[it - diff] xor longer.words[it]
            else longer.words[it]
        }, isOwned = true)
    }

    operator fun plus(summand: UByte): VarUInt {
        val result = bytes
        var carry = summand.toInt()
        for (i in result.lastIndex downTo 0) {
            val sum = result[i].toInt() + carry
            result[i] = sum.toUByte()
            carry = sum ushr 8
            if (carry == 0) return VarUInt(result)
        }
        return VarUInt(ubyteArrayOf(carry.toUByte(), *result))
    }

    /**
     * @throws IllegalArgumentException if the result would be negative
     */
    operator fun minus(subtrahend: UByte): VarUInt {
        val result = bytes
        var borrow = subtrahend.toInt()
        for (i in result.lastIndex downTo 0) {
            val diff = result[i].toInt() - borrow
            if (diff >= 0) {
                result[i] = diff.toUByte()
                // The subtraction may have zeroed the high byte(s); trim so the no-leading-zero invariant holds.
                return constructUnsafe(result)
            }
            result[i] = (diff + 256).toUByte()
            borrow = 1
        }
        throw IllegalArgumentException("Result would be negative")
    }


    infix fun shl(offset: Int): VarUInt {
        require(offset >= 0) { "offset must be non-negative: $offset" }
        if ((offset == 0) || this.isZero()) return this

        val highWordBits = 8 - (offset % 8)
        if (highWordBits == 8) return VarUInt(words.copyOf(words.size + (offset / 8)))

        val newSize = words.size + (offset / 8) + 1

        return constructFromUntrimmed(UByteArray(newSize) { i ->
            when {
                i == 0 -> words[i] shr highWordBits
                i < words.size -> combine(words[i - 1], words[i], highWordBits)
                i == words.size -> words[i - 1] shl 8 - highWordBits
                else -> 0x00u
            }
        }, isOwned = true)
    }

    infix fun shr(offset: Int): VarUInt {
        require(offset >= 0) { "offset must be non-negative: $offset" }
        if ((offset == 0) || this.isZero()) return this

        val newSize = words.size - (offset / 8)
        if (newSize <= 0) return ZERO

        val highWordBits = offset % 8
        if (highWordBits == 0) return VarUInt(words.copyOfRange(0, newSize))
        return constructFromUntrimmed(UByteArray(newSize) { i ->
            when {
                i > 0 -> combine(words[i - 1], words[i], highWordBits)
                else -> words[i] shr highWordBits
            }
        }, true)
    }

    fun toAsn1VarInt(): ByteArray = throughBuffer { it.writeAsn1VarInt(this) }

    fun isZero(): Boolean = (words.first() == 0.toUByte()) //always trimmed, so it is enough to inspect the first byte

    fun bitLength(): Int = 8 * (words.size - 1) + words.first().bitLength

    fun inv(): VarUInt = constructFromUntrimmed(UByteArray(words.size) { words[it].inv() }, true)


    operator fun compareTo(byte: UByte): Int = if (words.size > 1) 1 else words.last().compareTo(byte)


    /**
     * @throws IllegalArgumentException if the number is too large
     */
    @Throws(IllegalArgumentException::class)
    fun shortValue(): Int =
        if (words.size > 2) throw IllegalArgumentException("Number too large!")
        else if (words.size > 1) words.last().toInt() and (words[words.lastIndex - 1].toInt() shl 8)
        else words.last().toInt()


    companion object {
        val ZERO = VarUInt(ubyteArrayOf(0x00u))

        private fun constructFromUntrimmed(untrimmed: UByteArray, isOwned: Boolean): VarUInt {
            val i = untrimmed.indexOfFirst { it != 0x00u.toUByte() }
            return when {
                (i == -1) -> ZERO
                (i == 0 && isOwned) -> VarUInt(untrimmed)
                else -> VarUInt(untrimmed.copyOfRange(i, untrimmed.size))
            }
        }

        operator fun invoke(uByte: UByte = 0x00u) = constructFromUntrimmed(ubyteArrayOf(uByte), true)
        operator fun invoke(value: String) = constructFromUntrimmed(value.parseAsBase10().toUByteArray(), true)
        operator fun invoke(ubyteArray: UByteArray) = constructFromUntrimmed(ubyteArray, false)
        operator fun invoke(byteArray: ByteArray) = constructFromUntrimmed(byteArray.asUByteArray(), false)
        operator fun invoke(uLong: ULong) =
            constructFromUntrimmed(uLong.toTwosComplementByteArray().asUByteArray(), true)

        operator fun invoke(uInt: UInt) = constructFromUntrimmed(uInt.toTwosComplementByteArray().asUByteArray(), true)

        internal fun constructUnsafe(ownedArray: UByteArray) = constructFromUntrimmed(ownedArray, true)

        internal fun Sink.writeAsn1VarInt(number: VarUInt): Int {
            if (number.isZero()) {
                writeByte(0)
                return 1
            }
            val numBytes = (number.bitLength() + 6) / 7 // division rounding up

            (numBytes - 1).downTo(0).forEach { byteIndex ->
                writeByte(
                    ((number shr (byteIndex * 7)).words.last() and UVARINT_MASK_UBYTE).toByte() or
                            (if (byteIndex > 0) UVARINT_SINGLEBYTE_MAXVALUE else 0)
                )
            }
            return numBytes
        }

        private fun MutableList<Char>.divRem(d: Int): Pair<MutableList<Char>, Int> {
            val result = mutableListOf<Char>()
            var residue = 0
            // result * 256 + residue == (string[0..i])
            for (char in this) {
                val currentDigit = residue * 10 + char.digitToInt()
                result.add((currentDigit / d).digitToChar()) // Append the quotient
                residue = currentDigit % d // Update remainder
            }
            result.apply { while (isNotEmpty() && first() == '0') removeFirst() }
            return Pair(result, residue)
        }

        private fun String.parseAsBase10(): UByteArray {
            if (!matches(REGEX_BASE10)) throw Asn1Exception("Illegal input!")
            if (matches(REGEX_ZERO)) return ubyteArrayOf(0x00u)
            var currentValue = toMutableList()
            val byteList = mutableListOf<UByte>()
            while ((currentValue.size > 1) || (currentValue.size == 1 && currentValue.first() != '0')) {
                currentValue.divRem(256).let { (newValue, rem) ->
                    currentValue = newValue
                    byteList.add(rem.toUByte())
                }
            }
            return UByteArray(byteList.size) { byteList[byteList.size - it - 1] }
        }


        private fun Iterator<UByte>.toDecimalString(): String {
            // Initialize the result to hold the base-10 value
            var decimalResult = mutableListOf('0')

            // Process each byte in the base-256 array
            for (byte in this) {
                // Convert byte to an integer (unsigned)
                val value = byte.toInt() and 0xFF

                // Multiply the current decimal result by 256
                decimalResult = decimalResult.times256()

                // Add the new value
                decimalResult = decimalResult decimalPlus value.toString().toList()
            }

            return decimalResult.joinToString(separator = "")
        }

        // Function to multiply a large base-10 number (as a string) by 256
        private fun List<Char>.times256(): MutableList<Char> {
            var carry = 0
            val result = StringBuilder()

            for (digit in asReversed()) {
                val prod = digit.digitToInt() * 256 + carry
                result.append(prod % 10)
                carry = prod / 10
            }

            // Add remaining carry
            while (carry > 0) {
                result.append(carry % 10)
                carry /= 10
            }

            return result.reverse().toMutableList()
        }

        // Function to add two large base-10 numbers (as strings)
        internal infix fun List<Char>.decimalPlus(num2: List<Char>): MutableList<Char> {
            val result = StringBuilder()
            var carry = 0

            val (shorter, longer) = (if (size < num2.size) this to num2
            else num2 to this).let { (a, b) -> a.asReversed() to b.asReversed() }

            for (i in longer.indices) {
                val sum = (if (shorter.size > i) shorter[i].digitToInt() else 0) + longer[i].digitToInt() + carry
                result.append(sum % 10)
                carry = sum / 10
            }

            // Add remaining carry
            while (carry > 0) {
                result.append(carry % 10)
                carry /= 10
            }

            return result.reverse().toMutableList()
        }

        internal fun ByteArray.decodeAsn1VarBigUInt() = wrapInUnsafeSource().decodeAsn1VarBigUIntValue()

        internal fun ByteArray.decodeAsn1VarBigUIntValue(startIndex: Int, endIndex: Int = size): Pair<VarUInt, Int> {
            require(startIndex in 0..endIndex) { "Invalid bounds [$startIndex, $endIndex)" }
            require(endIndex <= size) { "End index $endIndex out of bounds for size $size" }
            var index = startIndex
            while (index < endIndex) {
                val current = this[index++].toUByte()
                if (current < 0x80.toUByte()) break
            }
            return decodeBase128Unsigned(startIndex, index) to index
        }

        internal fun Source<*>.decodeAsn1VarBigUIntValue(): VarUInt {
            val accumulator = ByteArrayBuffer()
            while (!exhausted()) {
                val current = readUByte()
                accumulator.writeUByte(current)
                if (current < 0x80.toUByte()) break
            }
            val encoded = accumulator.toByteArray()
            return encoded.decodeAsn1VarBigUIntValue(0, encoded.size).first
        }

        internal fun Source<*>.decodeAsn1VarBigUInt(): Pair<VarUInt, ByteArray> {
            val accumulator = ByteArrayBuffer()//TODO hog
            while (!exhausted()) {
                val current = readUByte()
                accumulator.writeUByte(current)
                if (current < 0x80.toUByte()) break
            }
            val encoded = accumulator.toByteArray()
            return encoded.decodeAsn1VarBigUIntValue(0, encoded.size).first to encoded
        }

        //resurrect old hand-rolled variant from 2022 for efficiency
        private fun ByteArray.decodeBase128Unsigned(startIndex: Int, endIndex: Int): VarUInt {
            if (startIndex == endIndex) return ZERO

            val result = UByteArray(((endIndex - startIndex) * 7 + 7) / 8)
            var outIndex = result.lastIndex
            var accumulator = 0
            var bitsInAccumulator = 0

            for (index in endIndex - 1 downTo startIndex) {
                accumulator = accumulator or ((this[index].toInt() and 0x7F) shl bitsInAccumulator)
                bitsInAccumulator += 7
                if (bitsInAccumulator >= 8) {
                    result[outIndex--] = accumulator.toUByte()
                    accumulator = accumulator ushr 8
                    bitsInAccumulator -= 8
                }
            }

            if (bitsInAccumulator > 0) result[outIndex] = accumulator.toUByte()
            // constructUnsafe trims leading zeroes.
            return constructUnsafe(result)
        }
    }
}

/**
 * String serializer for [Asn1Integer].
 *
 * Intended as a non-DER fallback representation for generic formats such as JSON.
 * When used with the `awesn1.kxs` DER format, this serializer is bypassed and native INTEGER DER TLV
 * encoding/decoding is used.
 */
object Asn1IntegerStringSerializer : KSerializer<Asn1Integer> {
    override val descriptor = PrimitiveSerialDescriptor(ASN1_DESCRIPTOR_INTEGER, PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): Asn1Integer =
        Asn1Integer.fromDecimalString(decoder.decodeString())


    override fun serialize(encoder: Encoder, value: Asn1Integer) {
        encoder.encodeString(value.toString())
    }

}

object Asn1IntegerPositiveSerializer : KSerializer<Asn1Integer.Positive> {
    override val descriptor: SerialDescriptor = Asn1Integer.serializer().descriptor

    override fun deserialize(decoder: Decoder): Asn1Integer.Positive =
        decoder.decodeSerializableValue(Asn1Integer.serializer()).let {
            it as? Asn1Integer.Positive
                ?: throw SerializationException("Expected non-negative ASN.1 INTEGER, got $it")
        }

    override fun serialize(encoder: Encoder, value: Asn1Integer.Positive) {
        encoder.encodeSerializableValue(Asn1Integer.serializer(), value)
    }
}

object Asn1IntegerNegativeSerializer : KSerializer<Asn1Integer.Negative> {
    override val descriptor: SerialDescriptor = Asn1Integer.serializer().descriptor

    override fun deserialize(decoder: Decoder): Asn1Integer.Negative =
        decoder.decodeSerializableValue(Asn1Integer.serializer()).let {
            it as? Asn1Integer.Negative
                ?: throw SerializationException("Expected negative ASN.1 INTEGER, got $it")
        }

    override fun serialize(encoder: Encoder, value: Asn1Integer.Negative) {
        encoder.encodeSerializableValue(Asn1Integer.serializer(), value)
    }
}
