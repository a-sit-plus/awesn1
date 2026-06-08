// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:Suppress("SERIALIZER_TYPE_INCOMPATIBLE")
@file:OptIn(InternalAwesn1Api::class)

package at.asitplus.awesn1

import at.asitplus.awesn1.encoding.*
import at.asitplus.awesn1.serialization.Asn1Serializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlin.math.pow
import kotlin.math.sign


private const val IEEE754_BIAS = 1023

/**
 * ASN.1 REAL number. Mind possible loss of precision compared to Kotlin's built-in types.
 * This type is irrelevant for PKI applications, but required for generic ASN.1 serialization
 */
@Serializable(with = Asn1Real.Companion::class)
sealed interface Asn1Real : Asn1Encodable<Asn1Primitive> {

    /**
     * Converts this Asn1Real to a [Float]. **Beware of *probable* loss of precision!**
     */
    fun toFloat() = toDouble().toFloat()

    /**
     * Converts this Asn1Real to a [Double]. **Beware of possible loss of precision!**
     */
    fun toDouble() = when (this) {
        is Finite -> (normalizedMantissa.toString().toDouble() * 2.0.pow(normalizedExponent.toDouble()))
        NegativeInfinity -> Double.NEGATIVE_INFINITY
        PositiveInfinity -> Double.POSITIVE_INFINITY
        PositiveZero -> 0.0
        NegativeZero -> -0.0
        NaN -> Double.NaN
    }

    @Deprecated(
        "Use Asn1Real.PositiveZero instead",
        ReplaceWith("Asn1Real.PositiveZero", "at.asitplus.awesn1.Asn1Real"),
        level = DeprecationLevel.ERROR,
    )
    typealias Zero = PositiveZero

    @Serializable(with = Asn1RealStringSerializer::class)
    object NegativeZero : Asn1Real

    @Serializable(with = Asn1RealStringSerializer::class)
    object PositiveZero : Asn1Real

    @Serializable(with = Asn1RealStringSerializer::class)
    object NaN : Asn1Real

    @Serializable(with = Asn1RealStringSerializer::class)
    object PositiveInfinity : Asn1Real

    @Serializable(with = Asn1RealStringSerializer::class)
    object NegativeInfinity : Asn1Real

    @Serializable(with = Asn1RealStringSerializer::class)
    @ConsistentCopyVisibility
    data class Finite internal constructor(val normalizedMantissa: Asn1Integer, val normalizedExponent: Long) :
        Asn1Real

    override fun encodeToTlv(): Asn1Primitive = encodeToAsn1Primitive()

    /** Encodes this number into a [ByteArray] using the same encoding as the [Asn1Primitive.content] property of an [Asn1Primitive] containing an ASN.1 REAL */
    fun encodeToAsn1ContentBytes(): ByteArray = when (this) {
        PositiveInfinity -> ContentBytesConstants.POSITIVE_INFINITY.copyOf()
        NegativeInfinity -> ContentBytesConstants.NEGATIVE_INFINITY.copyOf()
        PositiveZero -> ContentBytesConstants.POSITIVE_ZERO
        NegativeZero -> ContentBytesConstants.NEGATIVE_ZERO.copyOf()
        NaN -> ContentBytesConstants.NAN.copyOf()
        is Finite -> {
            val exponentOctets = normalizedExponent.toTwosComplementByteArray()
            val mantissaOctets = normalizedMantissa.magnitude

            val (exponentLengthEncoding, exponentLengthOctets) = when (exponentOctets.size) {
                1 -> 0 to byteArrayOf()
                2 -> 1 to byteArrayOf()
                3 -> 2 to byteArrayOf()
                else -> 3 to exponentOctets.size.toUnsignedByteArray() //this will never exceed 255 bytes, because Long spans 8 bytes at most
            }

            val signEncoding = if (normalizedMantissa.sign == Asn1Integer.Sign.NEGATIVE) 0x40 else 0
            val binaryEncoding = 0x80

            byteArrayOf(
                (binaryEncoding or signEncoding or exponentLengthEncoding).toByte(),
                *exponentLengthOctets,
                *exponentOctets,
                *mantissaOctets
            )
        }
    }

    companion object : Asn1Serializer<Asn1Primitive, Asn1Real>(
        leadingTags = setOf(Asn1Element.Tag.REAL),
        decodable = object : Asn1Decodable<Asn1Primitive, Asn1Real> {
            override fun doDecode(src: Asn1Primitive): Asn1Real = src.decodeToAsn1Real(src.tag)
        },
        fallbackSerializer = Asn1RealStringSerializer,
    ) {

        private object ContentBytesConstants {
            val POSITIVE_INFINITY = byteArrayOf(0x40)
            val NEGATIVE_INFINITY = byteArrayOf(0x41)
            val NEGATIVE_ZERO = byteArrayOf(0x43)
            val POSITIVE_ZERO = byteArrayOf()
            val NAN = byteArrayOf(0x42)
        }

        override val descriptor: SerialDescriptor =
            PrimitiveSerialDescriptor(ASN1_DESCRIPTOR_REAL, PrimitiveKind.STRING)

        /**
         * Converts a Double into an ASN.1 REAL.
         * **Beware of the fact that ASN.1 REAL zero knows no sign!**
         *
         * @throws Asn1Exception when passing [Double.NaN]
         */
        @Throws(Asn1Exception::class)
        operator fun invoke(number: Double): Asn1Real = runRethrowing {
            //if number is NaN, number == Double.NaN will return false. only number.isNaN() will return true
            if (number.isNaN()) NaN
            else when (number) {
                //Kotlin clearly represents -0.0 and 0.0 differently, but a check for -0.0 == 0.0 ALWAYS RETURNS TRUE. I can't even
                -0.0, 0.0 -> if (number.sign.compareTo(-0.0) == 0) NegativeZero else PositiveZero
                Double.NEGATIVE_INFINITY -> NegativeInfinity
                Double.POSITIVE_INFINITY -> PositiveInfinity
                else -> number.getAsn1RealComponents().let { (exponent, mantissa) -> Asn1Real(mantissa, exponent) }
            }
        }

        /**
         * Converts a Float into an ASN.1 REAL.
         *
         * @throws Asn1Exception when passing [Float.NaN]
         */
        @Throws(Asn1Exception::class)
        @Suppress("NOTHING_TO_INLINE")
        inline operator fun invoke(number: Float): Asn1Real = invoke(number.toDouble())


        operator fun invoke(
            mantissa: Asn1Integer,
            exponent: Long
        ): Asn1Real {
            if (mantissa == Asn1Integer.ZERO) return PositiveZero //no way to get negative zero from Asn1Integer.ZERO

            val trailingZeroBits = mantissa.magnitude.countTrailingZeroBits()
            val normalizedMantissa =
                Asn1Integer.fromByteArray(mantissa.uint.shr(trailingZeroBits).bytes.asByteArray(), mantissa.sign)
            val normalizedExponent = exponent + trailingZeroBits

            return Finite(normalizedMantissa, normalizedExponent)
        }


        private fun ByteArray.countTrailingZeroBits(): Int {
            var result = 0

            for (i in lastIndex downTo 0) {
                val byte = this[i].toInt() and 0xff

                if (byte == 0) {
                    result += 8
                } else {
                    return result + byte.countTrailingZeroBits()
                }
            }

            return result
        }

        private fun Double.getAsn1RealComponents(): Pair<Long, Asn1Integer> {
            val bits = this.toBits()
            val rawExponent = ((bits ushr 52) and 0x7FF).toInt() // 11 bits
            val rawMantissa = (bits and 0xFFFFFFFFFFFFF)// 52 bits

            val exponent = if (rawExponent == 0) {
                1 - IEEE754_BIAS - 52
            } else {
                rawExponent - IEEE754_BIAS - 52
            }
            // Normal: rawExponent != 0 => implicit leading 1
            val mantissa = if (rawExponent != 0) (1L shl 52) or rawMantissa else rawMantissa

            if (mantissa == 0L) {
                throw ImplementationError("Tried to get Asn1Real components of zero")
            }
            var normalizedExponent = exponent
            var normalizedMantissa = mantissa
            normalizedMantissa.countTrailingZeroBits().let { bits ->
                normalizedMantissa = normalizedMantissa shr bits
                normalizedExponent += bits
            }

            return normalizedExponent.toLong() to
                    if (this.sign == 1.0) Asn1Integer.Positive(VarUInt(normalizedMantissa.toUnsignedByteArray()))
                    else Asn1Integer.Negative(VarUInt(normalizedMantissa.toUnsignedByteArray()))
        }

        /**
         * Decodes a [Asn1Real] from [bytes] assuming the same encoding as the [Asn1Primitive.content] property of an [Asn1Primitive] containing an ASN.1 REAL
         *
         * @param lenient if `true` the function will not throw an exception if the input is not normalised, meaning:
         *   - mantissa and exponent can be used as-is with base `2`
         *   - mantissa and exponent are minimally encoded
         */
        @Throws(Asn1Exception::class)
        fun decodeFromAsn1ContentBytes(bytes: ByteArray, lenient: Boolean = false): Asn1Real = runRethrowing {

            return if (bytes contentEquals ContentBytesConstants.POSITIVE_ZERO) Asn1Real.PositiveZero
            else if (bytes contentEquals ContentBytesConstants.NEGATIVE_ZERO) Asn1Real.NegativeZero
            else if (bytes contentEquals ContentBytesConstants.NAN) Asn1Real.NaN
            else if (bytes.contentEquals(ContentBytesConstants.POSITIVE_INFINITY)) Asn1Real.PositiveInfinity
            else if (bytes.contentEquals(ContentBytesConstants.NEGATIVE_INFINITY)) Asn1Real.NegativeInfinity
            else {
                val identifierOctet = bytes.first().toInt() and 0xFF
                require((identifierOctet and 0x80) != 0) { "ASN.1 REAL is not binary encoded" }
                val sign =
                    if ((0x40 and identifierOctet) == 0) Asn1Integer.Sign.POSITIVE else Asn1Integer.Sign.NEGATIVE
                val (exponentLength, exponentOffset) = when (identifierOctet and 0b11) {
                    0 -> 1 to 1
                    1 -> 2 to 1
                    2 -> 3 to 1
                    else -> {
                        require(bytes.size >= 3) { "ASN.1 REAL content too short for extended exponent length" }
                        val explicitExponentLength = bytes[1].toInt() and 0xFF
                        require(explicitExponentLength > 0) { "ASN.1 REAL exponent length must be > 0" }
                        explicitExponentLength to 2
                    }
                }
                val mantissaOffset = exponentOffset + exponentLength
                require(bytes.size > mantissaOffset) { "ASN.1 REAL content missing mantissa" }

                val exponentSlice = bytes.copyOfRange(exponentOffset, mantissaOffset)
                val exponent = when (exponentLength) {
                    1 -> exponentSlice[0].toLong()
                    else -> Long.fromTwosComplementByteArray(exponentSlice)
                }
                val mantissa = VarUInt(bytes.copyOfRange(mantissaOffset, bytes.size))

                val decoded =
                    if (sign == Asn1Integer.Sign.POSITIVE) Asn1Real(Asn1Integer.Positive(mantissa), exponent)
                    else Asn1Real(Asn1Integer.Negative(mantissa), exponent)

                if (!lenient && !decoded.encodeToAsn1ContentBytes().contentEquals(bytes))
                    throw Asn1Exception(
                        "ASN.1 REAL is not minimally encoded. Is: ${bytes.toHexString()}, shouldBe: ${
                            decoded.encodeToAsn1ContentBytes().toHexString()
                        }"
                    )

                decoded
            }

        }

    }
}

/**
 * String serializer for [Asn1Real].
 *
 * Intended as a non-DER fallback representation for generic formats such as JSON.
 * When used with the `awesn1.kxs` DER format, this serializer is bypassed and native REAL DER TLV
 * encoding/decoding is used.
 */
object Asn1RealStringSerializer : KSerializer<Asn1Real> {
    override val descriptor: SerialDescriptor
        get() = PrimitiveSerialDescriptor(ASN1_DESCRIPTOR_REAL, PrimitiveKind.STRING)

    override fun serialize(
        encoder: Encoder,
        value: Asn1Real
    ) {
        val serializedValue = when (value) {
            //@formatter:off
            Asn1Real.PositiveZero       ->  "0.0"
            Asn1Real.NegativeZero       -> "-0.0"
            Asn1Real.PositiveInfinity   ->  "INF"
            Asn1Real.NegativeInfinity   -> "-INF"
            Asn1Real.NaN                ->  "NaN"
            //@formatter:on
            is Asn1Real.Finite -> {
                val mantissa = value.normalizedMantissa.toString()
                val exponent = value.normalizedExponent
                "$mantissa * 2^$exponent"
            }
        }
        encoder.encodeString(serializedValue)
    }

    override fun deserialize(decoder: Decoder): Asn1Real {
        val decodedString = decoder.decodeString()
        return when {
            //@formatter:off
            decodedString ==    "0" -> Asn1Real.PositiveZero
            decodedString ==  "0.0" -> Asn1Real.PositiveZero
            decodedString ==   "-0" -> Asn1Real.NegativeZero
            decodedString == "-0.0" -> Asn1Real.NegativeZero
            decodedString ==  "INF" -> Asn1Real.PositiveInfinity
            decodedString == "-INF" -> Asn1Real.NegativeInfinity
            decodedString ==  "NaN" -> Asn1Real.NaN
            //@formatter:on
            else -> {
                val parts = decodedString.replace("\\s".toRegex(), "").split("*2^")
                require(parts.size == 2) { "Invalid format for Asn1Real" }
                val mantissa = Asn1Integer.fromDecimalString(parts[0])
                val exponent = parts[1].toLong()
                Asn1Real(mantissa, exponent)
            }
        }
    }

}
