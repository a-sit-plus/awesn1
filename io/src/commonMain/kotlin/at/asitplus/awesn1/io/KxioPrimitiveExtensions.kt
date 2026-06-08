// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(at.asitplus.awesn1.InternalAwesn1Api::class)

package at.asitplus.awesn1.io

import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1Real
import at.asitplus.awesn1.encoding.*
import at.asitplus.awesn1.encoding.internal.*
import kotlinx.io.readByteArray
import kotlin.time.Instant

private fun kotlinx.io.Source.readAsn1ContentBytes(nBytes: Int): ByteArray {
    require(nBytes >= 0) { "nBytes must be non-negative" }
    return readByteArray(nBytes)
}

private fun kotlinx.io.Sink.writeAsn1ContentBytes(bytes: ByteArray): Int {
    write(bytes, 0, bytes.size)
    return bytes.size
}

fun kotlinx.io.Source.readAsn1BooleanContent(nBytes: Int = 1): Boolean =
    Boolean.decodeFromAsn1ContentBytes(readAsn1ContentBytes(nBytes))

/**
 * @param lenient Relaxes DER constraints, which are:
 * - The content of the `INTEGER` type is not empty.
 * - The `INTEGER` value is minimally encoded, verifying that:
 *     - Positive ints do not contain leading zero bytes unless necessary.
 *     - Negative ints do not use excessive sign extension bytes.
 */
fun kotlinx.io.Source.readAsn1IntContent(nBytes: Int, lenient: Boolean = false): Int =
    Int.decodeFromAsn1ContentBytes(readAsn1ContentBytes(nBytes), lenient)

/**
 * @param lenient Relaxes DER constraints, which are:
 * - The content of the `INTEGER` type is not empty.
 * - The `INTEGER` value is minimally encoded, verifying that:
 *     - Positive ints do not contain leading zero bytes unless necessary.
 *     - Negative ints do not use excessive sign extension bytes.
 */
fun kotlinx.io.Source.readAsn1LongContent(nBytes: Int, lenient: Boolean = false): Long =
    Long.decodeFromAsn1ContentBytes(readAsn1ContentBytes(nBytes), lenient)

/**
 * @param lenient Relaxes DER constraints, which are:
 * - The content of the `INTEGER` type is not empty.
 * - The `INTEGER` value is minimally encoded, verifying that:
 *     - Positive ints do not contain leading zero bytes unless necessary.
 *     - Negative ints do not use excessive sign extension bytes.
 */
fun kotlinx.io.Source.readAsn1UIntContent(nBytes: Int, lenient: Boolean = false): UInt =
    UInt.decodeFromAsn1ContentBytes(readAsn1ContentBytes(nBytes), lenient)

/**
 * @param lenient Relaxes DER constraints, which are:
 * - The content of the `INTEGER` type is not empty.
 * - The `INTEGER` value is minimally encoded, verifying that:
 *     - Positive ints do not contain leading zero bytes unless necessary.
 *     - Negative ints do not use excessive sign extension bytes.
 */
fun kotlinx.io.Source.readAsn1ULongContent(nBytes: Int, lenient: Boolean = false): ULong =
    ULong.decodeFromAsn1ContentBytes(readAsn1ContentBytes(nBytes), lenient)

/**
 * @param lenient Relaxes DER constraints, which are:
 * - The content of the `INTEGER` type is not empty.
 * - The `INTEGER` value is minimally encoded, verifying that:
 *     - Positive ints do not contain leading zero bytes unless necessary.
 *     - Negative ints do not use excessive sign extension bytes.
 */
fun kotlinx.io.Source.readAsn1ByteContent(nBytes: Int, lenient: Boolean = false): Byte =
    readAsn1IntContent(nBytes, lenient).also {
        require(it in Byte.MIN_VALUE..Byte.MAX_VALUE) { "Value $it is out of bounds for Byte" }
    }.toByte()

/**
 * @param lenient Relaxes DER constraints, which are:
 * - The content of the `INTEGER` type is not empty.
 * - The `INTEGER` value is minimally encoded, verifying that:
 *     - Positive ints do not contain leading zero bytes unless necessary.
 *     - Negative ints do not use excessive sign extension bytes.
 */
fun kotlinx.io.Source.readAsn1ShortContent(nBytes: Int, lenient: Boolean = false): Short =
    readAsn1IntContent(nBytes, lenient).also {
        require(it in Short.MIN_VALUE..Short.MAX_VALUE) { "Value $it is out of bounds for Short" }
    }.toShort()

/**
 * @param lenient Relaxes DER constraints, which are:
 * - The content of the `INTEGER` type is not empty.
 * - The `INTEGER` value is minimally encoded, verifying that:
 *     - Positive ints do not contain leading zero bytes unless necessary.
 *     - Negative ints do not use excessive sign extension bytes.
 */
fun kotlinx.io.Source.readAsn1UByteContent(nBytes: Int, lenient: Boolean = false): UByte =
    readAsn1UIntContent(nBytes, lenient).also {
        require(it <= UByte.MAX_VALUE.toUInt()) { "Value $it is out of bounds for UByte" }
    }.toUByte()

/**
 * @param lenient Relaxes DER constraints, which are:
 * - The content of the `INTEGER` type is not empty.
 * - The `INTEGER` value is minimally encoded, verifying that:
 *     - Positive ints do not contain leading zero bytes unless necessary.
 *     - Negative ints do not use excessive sign extension bytes.
 */
fun kotlinx.io.Source.readAsn1UShortContent(nBytes: Int, lenient: Boolean = false): UShort =
    readAsn1UIntContent(nBytes, lenient).also {
        require(it <= UShort.MAX_VALUE.toUInt()) { "Value $it is out of bounds for UShort" }
    }.toUShort()

/**
 * @param lenient Relaxes DER constraints, which are:
 * - The content of the `INTEGER` type is not empty.
 * - The `INTEGER` value is minimally encoded, verifying that:
 *     - Positive ints do not contain leading zero bytes unless necessary.
 *     - Negative ints do not use excessive sign extension bytes.
 */
fun kotlinx.io.Source.readAsn1Asn1IntegerContent(nBytes: Int, lenient: Boolean = false): Asn1Integer =
    Asn1Integer.decodeFromAsn1ContentBytes(readAsn1ContentBytes(nBytes), lenient)

fun kotlinx.io.Source.readAsn1RealContent(nBytes: Int): Asn1Real =
    Asn1Real.decodeFromAsn1ContentBytes(readAsn1ContentBytes(nBytes))

fun kotlinx.io.Source.readAsn1DoubleContent(nBytes: Int): Double =
    readAsn1RealContent(nBytes).toDouble()

fun kotlinx.io.Source.readAsn1FloatContent(nBytes: Int): Float =
    readAsn1RealContent(nBytes).toFloat()

fun kotlinx.io.Source.readAsn1StringContent(nBytes: Int): String =
    String.decodeFromAsn1ContentBytes(readAsn1ContentBytes(nBytes))

fun kotlinx.io.Source.readAsn1UtcTimeContent(nBytes: Int): Instant =
    Instant.decodeUtcTimeFromAsn1ContentBytes(readAsn1ContentBytes(nBytes))

fun kotlinx.io.Source.readAsn1GeneralizedTimeContent(nBytes: Int): Instant =
    Instant.decodeGeneralizedTimeFromAsn1ContentBytes(readAsn1ContentBytes(nBytes))

fun kotlinx.io.Sink.writeAsn1BooleanContent(value: Boolean): Int =
    writeAsn1ContentBytes(value.encodeToAsn1ContentBytes())

fun kotlinx.io.Sink.writeAsn1IntContent(value: Int): Int =
    writeAsn1ContentBytes(value.encodeToAsn1ContentBytes())

fun kotlinx.io.Sink.writeAsn1LongContent(value: Long): Int =
    writeAsn1ContentBytes(value.encodeToAsn1ContentBytes())

fun kotlinx.io.Sink.writeAsn1UIntContent(value: UInt): Int =
    writeAsn1ContentBytes(value.encodeToAsn1ContentBytes())

fun kotlinx.io.Sink.writeAsn1ULongContent(value: ULong): Int =
    writeAsn1ContentBytes(value.encodeToAsn1ContentBytes())

fun kotlinx.io.Sink.writeAsn1ByteContent(value: Byte): Int =
    writeAsn1IntContent(value.toInt())

fun kotlinx.io.Sink.writeAsn1ShortContent(value: Short): Int =
    writeAsn1IntContent(value.toInt())

fun kotlinx.io.Sink.writeAsn1UByteContent(value: UByte): Int =
    writeAsn1UIntContent(value.toUInt())

fun kotlinx.io.Sink.writeAsn1UShortContent(value: UShort): Int =
    writeAsn1UIntContent(value.toUInt())

fun kotlinx.io.Sink.writeAsn1Asn1IntegerContent(value: Asn1Integer): Int =
    writeAsn1ContentBytes(value.encodeToAsn1ContentBytes())

fun kotlinx.io.Sink.writeAsn1RealContent(value: Asn1Real): Int =
    writeAsn1ContentBytes(value.encodeToAsn1ContentBytes())

fun kotlinx.io.Sink.writeAsn1DoubleContent(value: Double): Int =
    writeAsn1RealContent(Asn1Real(value))

fun kotlinx.io.Sink.writeAsn1FloatContent(value: Float): Int =
    writeAsn1RealContent(Asn1Real(value))

fun kotlinx.io.Sink.writeAsn1StringContent(value: String): Int =
    writeAsn1ContentBytes(value.encodeToByteArray())

fun kotlinx.io.Sink.writeAsn1UtcTimeContent(value: Instant): Int =
    writeAsn1ContentBytes(value.encodeToAsn1UtcTimePrimitive().content)

fun kotlinx.io.Sink.writeAsn1GeneralizedTimeContent(value: Instant): Int =
    writeAsn1ContentBytes(value.encodeToAsn1GeneralizedTimePrimitive().content)

/**
 * @param lenient Relaxes DER constraints, which are:
 * - The content of the `INTEGER` type is not empty.
 * - The `INTEGER` value is minimally encoded, verifying that:
 *     - Positive ints do not contain leading zero bytes unless necessary.
 *     - Negative ints do not use excessive sign extension bytes.
 */
fun kotlinx.io.Source.readTwosComplementULong(nBytes: Int, lenient: Boolean = false): ULong =
    KxIoSource(this).readTwosComplementULong(nBytes, lenient)

/**
 * @param lenient Relaxes DER constraints, which are:
 * - The content of the `INTEGER` type is not empty.
 * - The `INTEGER` value is minimally encoded, verifying that:
 *     - Positive ints do not contain leading zero bytes unless necessary.
 *     - Negative ints do not use excessive sign extension bytes.
 */
fun kotlinx.io.Source.readTwosComplementLong(nBytes: Int, lenient: Boolean = false): Long =
    KxIoSource(this).readTwosComplementLong(nBytes, lenient)

/**
 * @param lenient Relaxes DER constraints, which are:
 * - The content of the `INTEGER` type is not empty.
 * - The `INTEGER` value is minimally encoded, verifying that:
 *     - Positive ints do not contain leading zero bytes unless necessary.
 *     - Negative ints do not use excessive sign extension bytes.
 */
fun kotlinx.io.Source.readTwosComplementInt(nBytes: Int, lenient: Boolean = false): Int =
    KxIoSource(this).readTwosComplementInt(nBytes, lenient)

/**
 * @param lenient Relaxes DER constraints, which are:
 * - The content of the `INTEGER` type is not empty.
 * - The `INTEGER` value is minimally encoded, verifying that:
 *     - Positive ints do not contain leading zero bytes unless necessary.
 *     - Negative ints do not use excessive sign extension bytes.
 */
fun kotlinx.io.Source.readTwosComplementUInt(nBytes: Int, lenient: Boolean = false): UInt =
    KxIoSource(this).readTwosComplementUInt(nBytes, lenient)

fun kotlinx.io.Sink.writeTwosComplementLong(value: Long): Int =
    KxIoSink(this).writeTwosComplementLong(value)

fun kotlinx.io.Sink.writeTwosComplementULong(value: ULong): Int =
    KxIoSink(this).writeTwosComplementULong(value)

fun kotlinx.io.Sink.writeTwosComplementUInt(value: UInt): Int =
    KxIoSink(this).writeTwosComplementUInt(value)

fun kotlinx.io.Sink.writeMagnitudeLong(value: Long): Int =
    KxIoSink(this).writeMagnitudeLong(value)
