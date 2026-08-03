// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(at.asitplus.awesn1.InternalAwesn1Api::class, ExperimentalUnsignedTypes::class)

package at.asitplus.awesn1

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
import kotlin.math.pow

private val REGEX_BASE10 = Regex("[0-9]+")

// default limit for toDecimalString (32 KB)
private const val DEFAULT_MAX_MAGNITUDE_BYTES = 32 * 1024
private const val DEFAULT_MAX_INPUT_LENGTH = (DEFAULT_MAX_MAGNITUDE_BYTES * 2410) / 1000 + 1

// number of bytes rendered for debugging before truncation
private const val DEBUGGING_MAGNITUDE_BYTES = 48

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

    /** Bounded hex representation. */
    override fun toString(): String = when (sign) {
        Sign.POSITIVE -> uint.toString("0x")
        Sign.NEGATIVE -> uint.toString("-0x")
    }

    /** Hex representation*/
    fun toHexString(): String = when (sign) {
        Sign.POSITIVE -> uint.toHexString("0x")
        Sign.NEGATIVE -> uint.toHexString("-0x")
    }

    /**
     * Renders this INTEGER as a decimal string.
     * O(n²) in byte length, so capped to [maxMagnitudeBytes] bytes.
     *
     * @throws Asn1Exception if the magnitude exceeds [maxMagnitudeBytes]
     */
    @Throws(Asn1Exception::class)
    fun toDecimalString(
        maxMagnitudeBytes: Int = DEFAULT_MAX_MAGNITUDE_BYTES,
    ) = when (sign) {
        Sign.POSITIVE -> uint.toDecimalString(maxMagnitudeBytes)
        Sign.NEGATIVE -> "-${uint.toDecimalString(maxMagnitudeBytes)}"
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
        fallbackSerializer = Asn1IntegerHexStringSerializer,
    ) {
        override val descriptor: SerialDescriptor =
            PrimitiveSerialDescriptor(ASN1_DESCRIPTOR_INTEGER, PrimitiveKind.STRING)

        val ONE by lazy { Asn1Integer.Positive(VarUInt(1u)) }
        val ZERO by lazy { Asn1Integer.Positive(VarUInt(0u)) }

        /**
         * Constructs an [Asn1Integer] from a decimal string.
         * O(n²) in the size, so bounded by [maxInputLength].
         * Input beyond this will throw.
         *
         * @throws Asn1Exception if the input length exceeds [maxInputLength]
         */
        @Throws(Asn1Exception::class, NumberFormatException::class)
        fun fromDecimalString(input: String, maxInputLength: Int = DEFAULT_MAX_INPUT_LENGTH): Asn1Integer =
            runRethrowing {
                if (input.isEmpty()) throw NumberFormatException("Empty input")
                //@formatter:off
            return when (input.first()) {
                '-' ->
                    fromSignMagnitude(VarUInt.fromDecimalString(input, fromOffset = 1, maxInputLength), Sign.NEGATIVE)
                '+' ->
                    fromSignMagnitude(VarUInt.fromDecimalString(input, fromOffset = 1, maxInputLength), Sign.POSITIVE)
                else ->
                    fromSignMagnitude(VarUInt.fromDecimalString(input, fromOffset = 0, maxInputLength), Sign.POSITIVE)
            }
            //@formatter:on
            }

        /**
         * Creates an Ans1Integer from a hex string. Valid inputs include:
         * * `0xCAFEBABE`
         * * `0xdeafbeef`
         * * `-badf00d`
         * * `+badf00d`
         * * `+0x1337`
         * * `-0xF00`
         */
        @Throws(NumberFormatException::class)
        fun fromHexString(input: String): Asn1Integer {
            if (input.isEmpty()) throw NumberFormatException("Empty input")
            //@formatter:off
            return when (input.first()) {
                '-' ->
                    fromSignMagnitude(VarUInt.fromHexString(input,1), Sign.NEGATIVE)
                '+' ->
                    fromSignMagnitude(VarUInt.fromHexString(input,1), Sign.POSITIVE)
                else ->
                    fromSignMagnitude(VarUInt.fromHexString(input), Sign.POSITIVE)
            }
            //@formatter:on
        }

        private fun fromSignMagnitude(magnitude: VarUInt, sign: Sign) = when {
            (sign == Sign.POSITIVE) || magnitude.isZero() -> Positive(magnitude)
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

/** Returns this value as an [Int], or throws [NumberFormatException] if it does not fit in one. */
@Throws(NumberFormatException::class)
fun Asn1Integer.toInt(): Int = toIntOrNull()
    ?: throw NumberFormatException("Asn1Integer does not fit into Int (bitLength=${uint.bitLength()})")

/** Returns this value as an [Int], or `null` if it does not fit in an [Int]. */
fun Asn1Integer.toIntOrNull(): Int? {
    // An in-range Int magnitude never exceeds 4 bytes (Int.MIN_VALUE = -2^31 -> magnitude 0x80000000).
    if (uint.words.size > 4) return null
    return toLongOrNull()?.takeIf { it in Int.MIN_VALUE.toLong()..Int.MAX_VALUE.toLong() }?.toInt()
}

/** Returns this value as a [Long], or throws [NumberFormatException] if it does not fit in one. */
@Throws(NumberFormatException::class)
fun Asn1Integer.toLong(): Long = toLongOrNull()
    ?: throw NumberFormatException("Asn1Integer does not fit into Long (bitLength=${uint.bitLength()})")

/** Returns this value as a [Long], or `null` if it does not fit in one. */
fun Asn1Integer.toLongOrNull(): Long? {
    // An in-range Long magnitude never exceeds 8 bytes (Long.MIN_VALUE = -2^63 -> magnitude 0x8000000000000000).
    if (uint.words.size > 8) return null
    var magnitude = 0uL // ULong holds the full unsigned 8-byte magnitude (up to 2^64-1) without overflow
    for (word in uint.words) magnitude = (magnitude shl 8) or word.toULong()
    return when (sign) {
        Asn1Integer.Sign.POSITIVE -> if (magnitude <= Long.MAX_VALUE.toULong()) magnitude.toLong() else null
        Asn1Integer.Sign.NEGATIVE -> when {
            magnitude <= Long.MAX_VALUE.toULong() -> -(magnitude.toLong())
            // Long.MIN_VALUE has magnitude 2^63 = Long.MAX_VALUE + 1, which does not fit in a positive Long.
            magnitude == Long.MAX_VALUE.toULong() + 1uL -> Long.MIN_VALUE
            else -> null
        }
    }
}

fun Asn1Integer.toDouble() = when (sign) {
    Asn1Integer.Sign.POSITIVE -> uint.toDouble()
    Asn1Integer.Sign.NEGATIVE -> uint.toDouble() * -1.0
}

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
internal value class VarUInt private constructor(
    /** the internal storage. never empty, always canonicalized (no leading zeros).
     * this is a direct accessor (it allows in-place mutation). with great power comes great responsibility. */
    val words: UByteArray
) {

    init {
        check(!words.isEmpty())
        check((words.size == 1) || (words.first() != 0x00u.toUByte()))
    }

    @Suppress("NOTHING_TO_INLINE")
    inline fun isEqualTo(other: VarUInt) = (words contentEquals other.words)

    /** a copy of the internal storage.
     * @see words */
    val bytes get() = words.copyOf()

    /** O(n^2) in number of bytes, therefore capped by [byteLimit]
     * @throws Asn1Exception if [byteLimit] is exceeded*/
    fun toDecimalString(byteLimit: Int = DEFAULT_MAX_MAGNITUDE_BYTES): String {
        if (words.size > byteLimit)
            throw Asn1Exception("Magnitude (${words.size} bytes) exceeds byte limit ($byteLimit bytes).")
        // Little-endian base-10^9 limbs (limbs[0] is least significant). Grows as needed.
        var limbs = IntArray(32) { 0 }
        var used = 1 // number of significant limbs (always >= 1; limbs[0]==0 represents zero)
        words.forEachIndexed { idx, byte ->
            var carry = (byte.toInt() and 0xFF).toLong()
            var i = 0
            while (i < used) {
                val cur = limbs[i].toLong() * 256L + carry
                limbs[i] = (cur % DECIMAL_RADIX).toInt()
                carry = cur / DECIMAL_RADIX
                i++
            }
            while (carry > 0L) {
                if (used == limbs.size) limbs = limbs.copyOf(limbs.size * 2)
                limbs[used++] = (carry % DECIMAL_RADIX).toInt()
                carry /= DECIMAL_RADIX
            }
        }
        // Emit most-significant limb without padding, every following limb zero-padded to 9 digits.
        var top = used - 1
        while (top > 0 && limbs[top] == 0) top--
        val sb = StringBuilder()
        sb.append(limbs[top])
        for (i in top - 1 downTo 0) {
            val limbStr = limbs[i].toString()
            repeat(DECIMAL_RADIX_DIGITS - limbStr.length) { sb.append('0') }
            sb.append(limbStr)
        }
        return sb.toString()
    }

    /** Bounded hex representation. */
    override fun toString() = toString("0x")
    fun toString(prefix: String) =
        toHexStringInternal(truncatePast = DEBUGGING_MAGNITUDE_BYTES, prefix = prefix)

    fun toHexString(prefix: String = "0x") =
        toHexStringInternal(prefix = prefix)

    private fun toHexStringInternal(truncatePast: Int = Int.MAX_VALUE, prefix: String = "0x"): String {
        val effectivePrefix = when {
            truncatePast < words.size -> "[truncated, ${words.size} bytes total] $prefix"
            else -> prefix
        }
        val effectiveSuffix = when {
            truncatePast < words.size -> "…"
            else -> ""
        }
        val overhead = effectivePrefix.length + effectiveSuffix.length
        val effectiveByteLimit = (Int.MAX_VALUE - overhead)/2 /* String maximum length */


        val renderEnd = minOf(truncatePast, words.size)
        require(renderEnd <= effectiveByteLimit)
            { "UVarInt (${words.size} bytes) is too long to be converted to String!" }

        val result = StringBuilder(renderEnd*2 + overhead)
        result.append(effectivePrefix)
        for (i in 0 until renderEnd) {
            val value = words[i].toInt()
            result.append(HEX_ALPHABET[value ushr 4])
            result.append(HEX_ALPHABET[value and 0x0f])
        }
        result.append(effectiveSuffix)
        return result.toString()
    }

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

    /** converts to a double. rounding behavior is slightly different from IEEE for performance. */
    fun toDouble(): Double {
        // IEEE 754 binary64 ("double"): 53 bits mantissa/significand, 11 bits exponent, 1 bit sign
        // so we take the leading (most significant) 54 bits, to account for rounding, and lose precision after that
        val firstByte = words[0]
        var result = firstByte.toDouble()
        var bitsToTake = 54 - firstByte.bitLength
        var i = 1
        while ((bitsToTake > 0) && i < words.size) {
            result *= 256.0
            result += words[i++].toDouble()
            bitsToTake -= 8
            // bitsToTake might be less than 0 here, but that's okay, we lose the last few to "normal" double math
        }
        // now multiply the remaining bits in
        result *= 256.0.pow(words.size - i)
        return result
    }


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
        operator fun invoke(ubyteArray: UByteArray) = constructFromUntrimmed(ubyteArray, false)
        operator fun invoke(byteArray: ByteArray) = constructFromUntrimmed(byteArray.asUByteArray(), false)
        operator fun invoke(uLong: ULong) =
            constructFromUntrimmed(uLong.toTwosComplementByteArray().asUByteArray(), true)

        operator fun invoke(uInt: UInt) = constructFromUntrimmed(uInt.toTwosComplementByteArray().asUByteArray(), true)

        internal fun constructUnsafe(ownedArray: UByteArray) = constructFromUntrimmed(ownedArray, true)

        @IgnorableReturnValue
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

        // 10^9 fits in an Int and is the largest power of ten whose product with 255 (a base-256 digit) still
        // fits in a Long, so a whole 9-decimal-digit limb can be multiply-accumulated in one Long operation.
        private const val DECIMAL_RADIX = 1_000_000_000L
        private const val DECIMAL_RADIX_DIGITS = 9

        /**
         * Parse decimal string [value] (starting at position [fromOffset] to VarUInt.
         * O(n²) in input length. Therefore, bounded to [maxInputLength] characters.
         * Excessive inputs throw.
         * @throws Asn1Exception on invalid or overlong input */
        @Throws(Asn1Exception::class)
        fun fromDecimalString(
            value: String, fromOffset: Int = 0,
            maxInputLength: Int = DEFAULT_MAX_INPUT_LENGTH
        ): VarUInt = runRethrowing {
            if (value.length > maxInputLength)
                throw Asn1Exception("Decimal string of ${value.length} characters exceeds limit ($maxInputLength).")
            if (REGEX_BASE10.matchAt(value, fromOffset)?.range?.last != value.lastIndex)
                throw NumberFormatException("Illegal input (not numerical)")
            val firstNonZero = value.indexOfFirst(startIndex = fromOffset) { it != '0' }
            if (firstNonZero == -1) return ZERO // input is all zeroes

            // Pack decimal digits into little-endian base-10^9 limbs, grouping 9 digits from the least significant end.
            val limbCount = (value.length - firstNonZero + DECIMAL_RADIX_DIGITS - 1) / DECIMAL_RADIX_DIGITS
            val limbs = IntArray(limbCount)
            var end = value.length
            var limbIndex = 0
            while (end > firstNonZero) {
                val start = maxOf(firstNonZero, end - DECIMAL_RADIX_DIGITS)
                limbs[limbIndex++] = value.substring(start, end).toInt()
                end = start
            }

            // Repeatedly divide the base-10^9 value by 256, collecting remainders as little-endian magnitude bytes.
            val byteListReversed = ArrayList<UByte>()
            var high = limbCount // number of still-significant limbs
            while (high > 0) {
                var rem = 0L
                for (i in high - 1 downTo 0) {
                    val cur = rem * DECIMAL_RADIX + limbs[i].toLong()
                    limbs[i] = (cur / 256L).toInt()
                    rem = cur % 256L
                }
                byteListReversed.add(rem.toUByte())
                while (high > 0 && limbs[high - 1] == 0) high--
            }
            // byteListReversed is little-endian, we need big-endian
            val result = UByteArray(byteListReversed.size) { byteListReversed[byteListReversed.size - 1 - it] }
            return constructFromUntrimmed(result, isOwned = true)
        }

        private const val HEX_ALPHABET = "0123456789abcdef"

        private fun hexDigit(c: Char): Int = when (c) {
            //TODO: replace with LUT, if we want even better perf, but not a prio
            in '0'..'9' -> c.code - '0'.code
            in 'a'..'f' -> c.code - 'a'.code + 10
            in 'A'..'F' -> c.code - 'A'.code + 10
            else -> -1
        }

        /** Lenient hex string parsing, strips 0x, whitespace and `:` */
        @Throws(Asn1Exception::class)
        fun fromHexString(hexString: String, offset: Int = 0): VarUInt = runRethrowing {
            var index = offset

            //pass over starting whitespace
            while (index < hexString.length && hexString[index].isWhitespace()) {
                index++
            }

            //pass over `0x`
            catchingUnwrapped {
                if (
                    index + 1 < hexString.length &&
                    hexString[index] == '0' &&
                    (hexString[index + 1] == 'x' || hexString[index + 1] == 'X')
                ) {
                    index += 2
                }
            }.onFailure { throw NumberFormatException(it.message) }

            if (index >= hexString.length) throw NumberFormatException("Not a hex string")

            //count actual jex digits, so we can allocate
            var digits = 0
            for (i in index until hexString.length) {
                val c = hexString[i]
                if (c != ':' && !c.isWhitespace()) {
                    if (hexDigit(c) < 0)
                        throw NumberFormatException("Invalid hex character '$c' at index $i")

                    digits++
                }
            }
            //alloc words + account for no leading zero
            val result = UByteArray((digits + 1) ushr 1)

            var byte = hexDigit(hexString[index])
            var output = 0
            if (digits % 2 == 0) {
                index++
                while (hexDigit(hexString[index]) == -1) index++
                byte = (byte shl 4) or hexDigit(hexString[index])
            }
            result[output] = byte.toUByte()
            output++
            var pending = false
            while (index + 1 < hexString.length) {
                index++
                if (hexDigit(hexString[index]) == -1) {
                    continue
                }
                if (!pending) {
                    pending = true
                    byte = hexDigit(hexString[index])
                    continue
                } else {
                    pending = false
                    byte = (byte shl 4) or hexDigit(hexString[index])
                }
                result[output] = byte.toUByte()
                output++

            }
            return VarUInt(words = result)

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
 *
 * Serialization uses [Asn1Integer.toDecimalString]/[Asn1Integer.fromDecimalString].
 * These functions are length limited.
 * The limits used by this serializer can be overridden (globally)
 *   using [decodingLimit]/[encodingLimit].
 * This only affects string serialization for non-DER formats.
 */
object Asn1IntegerDecimalStringSerializer : KSerializer<Asn1Integer> {
    override val descriptor = PrimitiveSerialDescriptor(ASN1_DESCRIPTOR_INTEGER, PrimitiveKind.STRING)

    /** maximum size (characters) for decoding. can only be increased, not decreased. */
    //@formatter:off
    var decodingLimit = DEFAULT_MAX_INPUT_LENGTH; set(v) { field = maxOf(field, v) }
    //@formatter:on
    override fun deserialize(decoder: Decoder): Asn1Integer =
        Asn1Integer.fromDecimalString(decoder.decodeString(), decodingLimit)

    /** maximum size (bytes) for encoding. can only be increased, not decreased. */
    //@formatter:off
    var encodingLimit = DEFAULT_MAX_MAGNITUDE_BYTES; set(v) { field = maxOf(field, v) }
    //@formatter:on
    override fun serialize(encoder: Encoder, value: Asn1Integer) {
        encoder.encodeString(value.toDecimalString(encodingLimit))
    }

}

/**
 * String serializer for [Asn1Integer].
 *
 * Intended as a non-DER fallback representation for generic formats such as JSON.
 * When used with the `awesn1.kxs` DER format, this serializer is bypassed and native INTEGER DER TLV
 * encoding/decoding is used.
 *
 * Serialization uses [Asn1Integer.toHexString]/[Asn1Integer.fromHexString].
 */
object Asn1IntegerHexStringSerializer : KSerializer<Asn1Integer> {
    override val descriptor = PrimitiveSerialDescriptor(ASN1_DESCRIPTOR_INTEGER, PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): Asn1Integer =
        Asn1Integer.fromHexString(decoder.decodeString())

    override fun serialize(encoder: Encoder, value: Asn1Integer) {
        encoder.encodeString(value.toHexString())
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
