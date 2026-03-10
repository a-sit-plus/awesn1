// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.encoding.internal

import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.InternalAwesn1Api
import at.asitplus.awesn1.VarUInt.Companion.decodeAsn1VarBigUInt
import at.asitplus.awesn1.VarUInt.Companion.writeAsn1VarInt
import at.asitplus.awesn1.encoding.UVARINT_MASK_UBYTE
import at.asitplus.awesn1.encoding.bitLength
import at.asitplus.awesn1.encoding.toTwosComplementByteArray
import kotlin.math.ceil


private const val UVARINT_SINGLEBYTE_MAXVALUE_UBYTE: UByte = 0x80u

/**
 * Encodes this number using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come
 *
 * @return the number of bytes written to the sink
 */

@InternalAwesn1Api
fun Sink.writeAsn1VarInt(number: ULong) = writeAsn1VarInt(number, ULong.SIZE_BITS)

/**
 * Encodes this number using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come
 *
 * @return the number of bytes written to the sink
 */

@InternalAwesn1Api
fun Sink.writeAsn1VarInt(number: UInt) = writeAsn1VarInt(number.toULong(), UInt.SIZE_BITS)

/**
 * Encodes this number using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come
 *
 * @return the number of bytes written to the sink
 */

@InternalAwesn1Api
private fun Sink.writeAsn1VarInt(number: ULong, bits: Int): Int {
    if (number == 0uL) { //fast case
        writeByte(0)
        return 1
    }
    val numBytes = (number.bitLength + 6) / 7 // division rounding up
    (numBytes - 1).downTo(0).forEach { byteIndex ->
        writeUByte(
            ((number shr (byteIndex * 7)).toUByte() and UVARINT_MASK_UBYTE) or
                    (if (byteIndex > 0) UVARINT_SINGLEBYTE_MAXVALUE_UBYTE else 0u)
        )
    }
    return numBytes
}


/**
 * Decodes an ASN.1 unsigned varint to an [ULong], copying all bytes from the source into a [ByteArray].
 *
 * @return the decoded [ULong] and the underlying varint-encoded bytes as [ByteArray]
 * @throws IllegalArgumentException if the number is larger than [ULong.MAX_VALUE]
 */
@Throws(IllegalArgumentException::class)
@InternalAwesn1Api
fun Source<*>.decodeAsn1VarULong(): Pair<ULong, ByteArray> = decodeAsn1VarInt(ULong.SIZE_BITS)

/**
 * Decodes an ASN.1 unsigned varint to an [UInt], copying all bytes from the source into a [ByteArray].
 *
 * @return the decoded [UInt] and the underlying varint-encoded bytes as [ByteArray]
 * @throws IllegalArgumentException if the number is larger than [UInt.MAX_VALUE]
 */
@Throws(IllegalArgumentException::class)
@InternalAwesn1Api
fun Source<*>.decodeAsn1VarUInt(): Pair<UInt, ByteArray> =
    decodeAsn1VarInt(UInt.SIZE_BITS).let { (n, b) -> n.toUInt() to b }

/**
 * Decodes an ASN.1 unsigned varint to an ULong allocating at most [bits] many bits .
 * This function is useful as an intermediate processing step, since it also returns a [at.asitplus.awesn1.encoding.internal.Buffer]
 * holding all bytes consumed from the source.
 * This operation essentially moves bytes around without copying.
 *
 * @return the decoded ASN.1 varint as an [ULong] and the underlying varint-encoded bytes as [at.asitplus.awesn1.encoding.internal.Buffer]
 * @throws IllegalArgumentException if the resulting number requires more than [bits] many bits to be represented
 */
@InternalAwesn1Api
@Throws(IllegalArgumentException::class)
private fun Source<*>.decodeAsn1VarInt(bits: Int): Pair<ULong, ByteArray> {
    var offset = 0
    var result = 0uL
    val accumulator = ByteArrayBuffer()
    while (!exhausted()) {
        val current = readUByte()
        accumulator.writeUByte(current)
        if (current >= UVARINT_SINGLEBYTE_MAXVALUE_UBYTE) {
            result = (current and UVARINT_MASK_UBYTE).toULong() or (result shl 7)
        } else {
            result = (current and UVARINT_MASK_UBYTE).toULong() or (result shl 7)
            break
        }
        if (++offset > ceil((bits * 8).toFloat() * 8f / 7f)) throw IllegalArgumentException("Number too Large do decode into $bits bits!")
    }

    return result to accumulator.toByteArray()
}

/**
 * Writes a signed long using twos-complement encoding using the fewest bytes required
 *
 * @return the number of byte written to the sink
 */
@InternalAwesn1Api
fun Sink.writeTwosComplementLong(number: Long): Int = appendUnsafe(number.toTwosComplementByteArray())

/**
 * Encodes an unsigned Long to a minimum-size twos-complement byte array
 * @return the number of bytes written
 */
@InternalAwesn1Api
fun Sink.writeTwosComplementULong(number: ULong): Int = appendUnsafe(number.toTwosComplementByteArray())


/** Encodes an unsigned Int to a minimum-size twos-complement byte array
 * @return the number of bytes written to the sink
 */
@InternalAwesn1Api
fun Sink.writeTwosComplementUInt(number: UInt) = writeTwosComplementLong(number.toLong())

/**
 * Consumes exactly [nBytes] from this source and interprets it as a signed [ULong].
 *
 * @throws IllegalArgumentException if too much or too little data is present
 */
@Throws(IllegalArgumentException::class)
@InternalAwesn1Api
fun Source<*>.readTwosComplementULong(nBytes: Int): ULong {
    if (nBytes == 9) {
        val leading = readByte()
        require(leading == 0.toByte()) { "Value with leading byte $leading is out of bounds for ULong" }
        var result = 0uL
        repeat(8) {
            result = (result shl 8) or readByte().toUByte().toULong()
        }
        return result
    }
    val signed = readTwosComplementLong(nBytes)
    require(signed >= 0) { "Value $signed is out of bounds for ULong" }
    return signed.toULong()
}


/**
 * Consumes exactly [nBytes] from this source and interprets it as a [Long].
 *
 * @throws IllegalArgumentException if too much or too little data is present
 */
@Throws(IllegalArgumentException::class)
@InternalAwesn1Api
fun Source<*>.readTwosComplementLong(nBytes: Int): Long {
    require(nBytes in 1..Long.SIZE_BYTES) { "Input with size $nBytes is out of bounds for Long" }
    var value = readByte().toLong() // signed top byte, so sign extension is preserved
    repeat(nBytes - 1) {
        value = (value shl 8) or readByte().toUByte().toLong()
    }
    return value
}


/**
 * Consumes exactly [nBytes] from this source and interprets it as a signed [Int]
 *
 * @throws IllegalArgumentException if too much or too little data is present
 */
@Throws(IllegalArgumentException::class)
@InternalAwesn1Api
fun Source<*>.readTwosComplementInt(nBytes: Int): Int {
    require(nBytes in 1..Int.SIZE_BYTES) { "Input with size $nBytes is out of bounds for Int" }
    var value = readByte().toInt() // signed top byte, so sign extension is preserved
    repeat(nBytes - 1) {
        value = (value shl 8) or readByte().toUByte().toInt()
    }
    return value
}

/**
 * Consumes exactly [nBytes] remaining data from this source and interprets it as a [UInt]
 *
 * @throws IllegalArgumentException if no or too much data is present
 */
@Throws(IllegalArgumentException::class)
@InternalAwesn1Api
fun Source<*>.readTwosComplementUInt(nBytes: Int): UInt {
    val signed = readTwosComplementLong(nBytes)
    require((0 <= signed) && (signed <= 0xFFFFFFFFL)) { "Value $signed is out of bounds for UInt" }
    return signed.toUInt()
}

/**
 *  Encodes a positive Long to a minimum-size unsigned byte array, omitting the leading zero
 *
 *  @throws IllegalArgumentException if [number] is negative
 *  @return the number of bytes written
 */
@InternalAwesn1Api
fun Sink.writeMagnitudeLong(number: Long): Int {
    require(number >= 0)
    return number.toTwosComplementByteArray().let { appendUnsafe(it, if (it[0] == 0.toByte()) 1 else 0) }
}


/**
 * Encodes this number using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come
 *
 * @return the number of bytes written to the sink
 */
@Throws(IllegalArgumentException::class)
@InternalAwesn1Api
fun Sink.writeAsn1VarInt(number: Asn1Integer): Int {
    require(number is Asn1Integer.Positive) { "Only non-negative numbers are supported" }
    return writeAsn1VarInt(number.uint)
}

/**
 * Decodes an ASN.1 unsigned varint to a [Asn1Integer], copying all bytes from the source into a [ByteArray].
 *
 * @return the decoded [Asn1Integer] and the underlying varint-encoded bytes as [ByteArray]
 */
@InternalAwesn1Api
fun Source<*>.decodeAsn1VarBigInt(): Pair<Asn1Integer, ByteArray> =
    decodeAsn1VarBigUInt().let { (uint, bytes) -> Asn1Integer.Positive(uint) to bytes }