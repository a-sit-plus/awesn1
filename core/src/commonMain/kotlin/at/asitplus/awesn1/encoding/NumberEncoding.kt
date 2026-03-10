// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(at.asitplus.awesn1.InternalAwesn1Api::class)

package at.asitplus.awesn1.encoding

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.internal.decodeAsn1VarBigInt
import at.asitplus.awesn1.encoding.internal.decodeAsn1VarUInt
import at.asitplus.awesn1.encoding.internal.decodeAsn1VarULong
import at.asitplus.awesn1.encoding.internal.readTwosComplementInt
import at.asitplus.awesn1.encoding.internal.readTwosComplementLong
import at.asitplus.awesn1.encoding.internal.readTwosComplementULong
import at.asitplus.awesn1.encoding.internal.writeAsn1VarInt
import at.asitplus.awesn1.encoding.internal.writeMagnitudeLong

internal const val UVARINT_SINGLEBYTE_MAXVALUE: Byte = 0x80.toByte()
internal const val UVARINT_MASK_UBYTE: UByte = 0x7Fu

/**
 * Encode as a four-byte array
 */
fun Int.encodeTo4Bytes(): ByteArray = byteArrayOf(
    (this ushr 24).toByte(),
    (this ushr 16).toByte(),
    (this ushr 8).toByte(),
    (this).toByte()
)

/**
 * Encode as an eight-byte array
 */
fun Long.encodeTo8Bytes(): ByteArray = byteArrayOf(
    (this ushr 56).toByte(),
    (this ushr 48).toByte(),
    (this ushr 40).toByte(),
    (this ushr 32).toByte(),
    (this ushr 24).toByte(),
    (this ushr 16).toByte(),
    (this ushr 8).toByte(),
    (this).toByte()
)

/** Encodes an unsigned Long to a minimum-size twos-complement byte array */
fun ULong.toTwosComplementByteArray() = when {
    this >= 0x8000000000000000UL ->
        byteArrayOf(
            0x00,
            (this shr 56).toByte(),
            (this shr 48).toByte(),
            (this shr 40).toByte(),
            (this shr 32).toByte(),
            (this shr 24).toByte(),
            (this shr 16).toByte(),
            (this shr 8).toByte(),
            this.toByte()
        )

    else -> this.toLong().toTwosComplementByteArray()
}

/** Encodes an unsigned Int to a minimum-size twos-complement byte array */
fun UInt.toTwosComplementByteArray() = toLong().toTwosComplementByteArray()

/** Encodes a signed Long to a minimum-size twos-complement byte array */
fun Long.toTwosComplementByteArray() = when {
    (this >= -0x80L && this <= 0x7FL) ->
        byteArrayOf(
            this.toByte()
        )

    (this >= -0x8000L && this <= 0x7FFFL) ->
        byteArrayOf(
            (this ushr 8).toByte(),
            this.toByte()
        )

    (this >= -0x800000L && this <= 0x7FFFFFL) ->
        byteArrayOf(
            (this ushr 16).toByte(),
            (this ushr 8).toByte(),
            this.toByte()
        )

    (this >= -0x80000000L && this <= 0x7FFFFFFFL) ->
        byteArrayOf(
            (this ushr 24).toByte(),
            (this ushr 16).toByte(),
            (this ushr 8).toByte(),
            this.toByte()
        )

    (this >= -0x8000000000L && this <= 0x7FFFFFFFFFL) ->
        byteArrayOf(
            (this ushr 32).toByte(),
            (this ushr 24).toByte(),
            (this ushr 16).toByte(),
            (this ushr 8).toByte(),
            this.toByte()
        )

    (this >= -0x800000000000L && this <= 0x7FFFFFFFFFFFL) ->
        byteArrayOf(
            (this ushr 40).toByte(),
            (this ushr 32).toByte(),
            (this ushr 24).toByte(),
            (this ushr 16).toByte(),
            (this ushr 8).toByte(),
            this.toByte()
        )

    (this >= -0x80000000000000L && this <= 0x7FFFFFFFFFFFFFL) ->
        byteArrayOf(
            (this ushr 48).toByte(),
            (this ushr 40).toByte(),
            (this ushr 32).toByte(),
            (this ushr 24).toByte(),
            (this ushr 16).toByte(),
            (this ushr 8).toByte(),
            this.toByte()
        )

    else ->
        byteArrayOf(
            (this ushr 56).toByte(),
            (this ushr 48).toByte(),
            (this ushr 40).toByte(),
            (this ushr 32).toByte(),
            (this ushr 24).toByte(),
            (this ushr 16).toByte(),
            (this ushr 8).toByte(),
            this.toByte()
        )
}

/** Encodes a signed Int to a minimum-size twos-complement byte array */
fun Int.toTwosComplementByteArray() = toLong().toTwosComplementByteArray()

fun Int.Companion.fromTwosComplementByteArray(it: ByteArray) =
    it.wrapInUnsafeSource().readTwosComplementInt(it.size)

fun UInt.Companion.fromTwosComplementByteArray(it: ByteArray) =
    it.wrapInUnsafeSource().readTwosComplementLong(it.size).let {
        require((0 <= it) && (it <= 0xFFFFFFFFL)) { "Value $it is out of bounds for UInt" }
        it.toUInt()
    }

fun Long.Companion.fromTwosComplementByteArray(it: ByteArray) =
    it.wrapInUnsafeSource().readTwosComplementLong(it.size)

fun ULong.Companion.fromTwosComplementByteArray(it: ByteArray) =
    it.wrapInUnsafeSource().readTwosComplementULong(it.size)

/** Encodes an unsigned Long to a minimum-size unsigned byte array */
fun Long.toUnsignedByteArray(): ByteArray = throughBuffer { it.writeMagnitudeLong(this) }

/** Encodes an unsigned Int to a minimum-size unsigned byte array */
fun Int.toUnsignedByteArray() = toLong().toUnsignedByteArray()


/**
 * Encodes this number using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come
 */
fun ULong.toAsn1VarInt(): ByteArray = throughBuffer { it.writeAsn1VarInt(this) }

/**
 * Encodes this number using unsigned VarInt encoding as used within ASN.1:
 * Groups of seven bits are encoded into a byte, while the highest bit indicates if more bytes are to come.
 *
 * This kind of encoding is used to encode [ObjectIdentifier] nodes and ASN.1 Tag values > 30
 */
fun UInt.toAsn1VarInt(): ByteArray = throughBuffer { it.writeAsn1VarInt(this) }

private fun List<Byte>.asn1VarIntByteMask(it: Int) =
    (if (isLastIndex(it)) 0x00 else UVARINT_SINGLEBYTE_MAXVALUE)

private fun List<Byte>.isLastIndex(it: Int) = it == size - 1

private fun List<Byte>.fromBack(it: Int) = this[size - 1 - it]


/**
 * Decodes an ULong from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * @return the decoded ULong and the underlying varint-encoded bytes as `ByteArray`
 * @throws IllegalArgumentException if the number is larger than [ULong.MAX_VALUE]
 */
@Throws(IllegalArgumentException::class)
fun ByteArray.decodeAsn1VarULong(): Pair<ULong, ByteArray> = this.throughBuffer { it.decodeAsn1VarULong() }

/**
 * Decodes an UInt from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * @return the decoded UInt and the underlying varint-encoded bytes as `ByteArray`
 * @throws IllegalArgumentException if the number is larger than [UInt.MAX_VALUE]
 */
@Throws(IllegalArgumentException::class)
fun ByteArray.decodeAsn1VarUInt(): Pair<UInt, ByteArray> = this.throughBuffer { it.decodeAsn1VarUInt() }



/** the number of bits required to represent this number */
val ULong.bitLength inline get() = ULong.SIZE_BITS - this.countLeadingZeroBits()

/** the number of bits required to represent this number */
val Long.bitLength inline get() = Long.SIZE_BITS - this.countLeadingZeroBits()

/** the number of bits required to represent this number */
val UInt.bitLength inline get() = UInt.SIZE_BITS - this.countLeadingZeroBits()

/** the number of bits required to represent this number */
val UByte.bitLength inline get() = UByte.SIZE_BITS - this.countLeadingZeroBits()

/** the number of bits required to represent this number */
val Int.bitLength inline get() = Int.SIZE_BITS - this.countLeadingZeroBits()


/**
 * Encodes this number using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come
 */
@Throws(IllegalArgumentException::class)
fun Asn1Integer.toAsn1VarInt(): ByteArray = throughBuffer { it.writeAsn1VarInt(this) }


/**
 * Decodes an unsigned [Asn1Integer] from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * @return the decoded unsigned BigInteger and the underlying varint-encoded bytes as `ByteArray`
 */
fun ByteArray.decodeAsn1VarBigInt(): Pair<Asn1Integer, ByteArray> = this.throughBuffer { it.decodeAsn1VarBigInt() }
