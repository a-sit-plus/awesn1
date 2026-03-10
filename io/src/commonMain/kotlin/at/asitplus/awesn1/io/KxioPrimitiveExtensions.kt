// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(at.asitplus.awesn1.InternalAwesn1Api::class)

package at.asitplus.awesn1.io

import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1Real
import at.asitplus.awesn1.encoding.decodeFromAsn1ContentBytes
import at.asitplus.awesn1.encoding.decodeGeneralizedTimeFromAsn1ContentBytes
import at.asitplus.awesn1.encoding.decodeUtcTimeFromAsn1ContentBytes
import at.asitplus.awesn1.encoding.encodeToAsn1ContentBytes
import at.asitplus.awesn1.encoding.encodeToAsn1GeneralizedTimePrimitive
import at.asitplus.awesn1.encoding.encodeToAsn1UtcTimePrimitive
import at.asitplus.awesn1.encoding.KxIoSink
import at.asitplus.awesn1.encoding.KxIoSource
import at.asitplus.awesn1.encoding.internal.readTwosComplementInt
import at.asitplus.awesn1.encoding.internal.readTwosComplementLong
import at.asitplus.awesn1.encoding.internal.readTwosComplementUInt
import at.asitplus.awesn1.encoding.internal.readTwosComplementULong
import at.asitplus.awesn1.encoding.internal.writeMagnitudeLong
import at.asitplus.awesn1.encoding.internal.writeTwosComplementLong
import at.asitplus.awesn1.encoding.internal.writeTwosComplementUInt
import at.asitplus.awesn1.encoding.internal.writeTwosComplementULong
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

fun kotlinx.io.Source.readAsn1IntContent(nBytes: Int): Int =
    Int.decodeFromAsn1ContentBytes(readAsn1ContentBytes(nBytes))

fun kotlinx.io.Source.readAsn1LongContent(nBytes: Int): Long =
    Long.decodeFromAsn1ContentBytes(readAsn1ContentBytes(nBytes))

fun kotlinx.io.Source.readAsn1UIntContent(nBytes: Int): UInt =
    UInt.decodeFromAsn1ContentBytes(readAsn1ContentBytes(nBytes))

fun kotlinx.io.Source.readAsn1ULongContent(nBytes: Int): ULong =
    ULong.decodeFromAsn1ContentBytes(readAsn1ContentBytes(nBytes))

fun kotlinx.io.Source.readAsn1ByteContent(nBytes: Int): Byte =
    readAsn1IntContent(nBytes).also {
        require(it in Byte.MIN_VALUE..Byte.MAX_VALUE) { "Value $it is out of bounds for Byte" }
    }.toByte()

fun kotlinx.io.Source.readAsn1ShortContent(nBytes: Int): Short =
    readAsn1IntContent(nBytes).also {
        require(it in Short.MIN_VALUE..Short.MAX_VALUE) { "Value $it is out of bounds for Short" }
    }.toShort()

fun kotlinx.io.Source.readAsn1UByteContent(nBytes: Int): UByte =
    readAsn1UIntContent(nBytes).also {
        require(it <= UByte.MAX_VALUE.toUInt()) { "Value $it is out of bounds for UByte" }
    }.toUByte()

fun kotlinx.io.Source.readAsn1UShortContent(nBytes: Int): UShort =
    readAsn1UIntContent(nBytes).also {
        require(it <= UShort.MAX_VALUE.toUInt()) { "Value $it is out of bounds for UShort" }
    }.toUShort()

fun kotlinx.io.Source.readAsn1Asn1IntegerContent(nBytes: Int): Asn1Integer =
    Asn1Integer.decodeFromAsn1ContentBytes(readAsn1ContentBytes(nBytes))

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

fun kotlinx.io.Source.readTwosComplementULong(nBytes: Int): ULong =
    KxIoSource(this).readTwosComplementULong(nBytes)

fun kotlinx.io.Source.readTwosComplementLong(nBytes: Int): Long =
    KxIoSource(this).readTwosComplementLong(nBytes)

fun kotlinx.io.Source.readTwosComplementInt(nBytes: Int): Int =
    KxIoSource(this).readTwosComplementInt(nBytes)

fun kotlinx.io.Source.readTwosComplementUInt(nBytes: Int): UInt =
    KxIoSource(this).readTwosComplementUInt(nBytes)

fun kotlinx.io.Sink.writeTwosComplementLong(value: Long): Int =
    KxIoSink(this).writeTwosComplementLong(value)

fun kotlinx.io.Sink.writeTwosComplementULong(value: ULong): Int =
    KxIoSink(this).writeTwosComplementULong(value)

fun kotlinx.io.Sink.writeTwosComplementUInt(value: UInt): Int =
    KxIoSink(this).writeTwosComplementUInt(value)

fun kotlinx.io.Sink.writeMagnitudeLong(value: Long): Int =
    KxIoSink(this).writeMagnitudeLong(value)
