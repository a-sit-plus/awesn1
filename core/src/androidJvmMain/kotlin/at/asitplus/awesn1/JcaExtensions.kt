package at.asitplus.awesn1

import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.encodeToAsn1Primitive
import kotlinx.io.Buffer
import kotlinx.io.Sink
import kotlinx.io.readByteArray
import java.math.BigInteger
import kotlin.div
import kotlin.experimental.and
import kotlin.experimental.or
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

private fun Asn1Integer.Sign.toJavaBigIntegerSign() = when (this) {
    Asn1Integer.Sign.POSITIVE -> 1
    Asn1Integer.Sign.NEGATIVE -> -1
}

fun Asn1Integer.toJavaBigInteger() =
    BigInteger(this.sign.toJavaBigIntegerSign(), this.magnitude)

fun BigInteger.toAsn1Integer() =
    Asn1Integer.fromByteArray(
        magnitude = this.abs().toByteArray(),
        sign = if (this.signum() < 0) Asn1Integer.Sign.NEGATIVE else Asn1Integer.Sign.POSITIVE)

fun Asn1.Int(value: BigInteger) = Int(value.toAsn1Integer())

/**
 * Converts this UUID to a BigInteger representation
 */
@OptIn(ExperimentalUuidApi::class)
fun Uuid.toBigInteger(): BigInteger = BigInteger(1,toByteArray())

/**
 * Tries to convert a BigInteger to a UUID. Only guaranteed to work with BigIntegers that contain the unsigned (positive)
 * integer representation of a UUID, chances are high, though, that it works with random positive BigIntegers between
 * 16 and 14 bytes long.
 *
 * Returns `null` if conversion fails. Never throws.
 */
@OptIn(ExperimentalUuidApi::class)
fun Uuid.Companion.fromBigintOrNull(bigInteger: BigInteger): Uuid? =
    catchingUnwrapped { fromByteArray(bigInteger.toByteArray().ensureSize(16)) }.getOrNull()


/**
 * Encodes this number using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come
 *
 * @return the number of bytes written to the sink
 */
@Throws(IllegalArgumentException::class)
fun Sink.writeAsn1VarInt(number: BigInteger): Int {
    if (number == BigInteger.ZERO) { //fast case
        writeByte(0)
        return 1
    }
    require(number.signum()>=0) { "Only non-negative numbers are supported" }
    val numBytes = (number.bitLength() + 6) / 7 // division rounding up
    (numBytes - 1).downTo(0).forEach { byteIndex ->
        writeByte(
            ((number shr (byteIndex * 7)).toByte() and 0x7F) or
                    (if (byteIndex > 0) 0x80.toByte() else 0)
        )
    }
    return numBytes
}

/**
 * Encodes this number using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come
 */
@Throws(IllegalArgumentException::class)
fun BigInteger.toAsn1VarInt(): ByteArray = Buffer().also { it.writeAsn1VarInt(this) }.readByteArray()
