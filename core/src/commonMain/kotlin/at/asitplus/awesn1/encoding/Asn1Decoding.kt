// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(at.asitplus.awesn1.InternalAwesn1Api::class)
@file:Suppress("NOTHING_TO_INLINE")

package at.asitplus.awesn1.encoding


import at.asitplus.awesn1.*
import at.asitplus.awesn1.BERTags.BMP_STRING
import at.asitplus.awesn1.BERTags.IA5_STRING
import at.asitplus.awesn1.BERTags.NUMERIC_STRING
import at.asitplus.awesn1.BERTags.PRINTABLE_STRING
import at.asitplus.awesn1.BERTags.T61_STRING
import at.asitplus.awesn1.BERTags.UNIVERSAL_STRING
import at.asitplus.awesn1.BERTags.UTF8_STRING
import at.asitplus.awesn1.BERTags.VISIBLE_STRING
import at.asitplus.awesn1.encoding.internal.decodeFromDer
import at.asitplus.awesn1.encoding.internal.parse
import at.asitplus.awesn1.encoding.internal.parseAll
import at.asitplus.awesn1.encoding.internal.parseFirst
import kotlin.enums.enumEntries
import kotlin.time.Instant



/**
 * Parses the provided [source] into a single [Asn1Element]. Consumes all bytes and throws if more than one ASN.1 structure was found or trailing bytes were detected.
 * @return the parsed [Asn1Element]
 *
 * @throws Asn1Exception on invalid input or if more than a single root structure was contained in the [source]
 */
@Throws(Asn1Exception::class)
fun Asn1Element.Companion.parse(source: ByteArray): Asn1Element =
    parse(source.wrapInUnsafeSource())

/**
 * Convenience wrapper around [parseAll], taking a [ByteArray] as [source]
 * @see parse
 */
@Throws(Asn1Exception::class)
fun Asn1Element.Companion.parseAll(source: ByteArray): List<Asn1Element> =
    parseAll(source.wrapInUnsafeSource())

/**
 * Convenience wrapper around [parseFirst], taking a [ByteArray] as [source].
 * @return a pair of the first parsed [Asn1Element] mapped to the remaining bytes
 * @see at.asitplus.awesn1.encoding.internal.readAsn1Element
 */
@Throws(Asn1Exception::class)
fun Asn1Element.Companion.parseFirst(source: ByteArray): Pair<Asn1Element, ByteArray> =
    parseFirst(source.wrapInUnsafeSource())
        .let { Pair(it.first, source.copyOfRange(it.second.toInt(), source.size)) }


/**
 * decodes this [Asn1Primitive]'s content into an [Boolean]. [assertTag] defaults to [Asn1Element.Tag.BOOL], but can be
 * overridden (for implicitly tagged booleans, for example)
 * @throws [Asn1Exception] all sorts of exceptions on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.decodeToBoolean(assertTag: Asn1Element.Tag = Asn1Element.Tag.BOOL) =
    runRethrowing { decode(assertTag) { Boolean.decodeFromAsn1ContentBytes(it) } }

/** Exception-free version of [decodeToBoolean] */
fun Asn1Primitive.decodeToBooleanOrNull(assertTag: Asn1Element.Tag = Asn1Element.Tag.BOOL) =
    catchingUnwrapped { decodeToBoolean(assertTag) }.getOrNull()

/**
 * decodes this [Asn1Primitive]'s content into an enum ordinal represented as [Long]. [assertTag] defaults to [Asn1Element.Tag.ENUM], but can be
 * overridden (for implicitly tagged enums, for example)
 * @throws [Asn1Exception] on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.decodeToEnumOrdinal(assertTag: Asn1Element.Tag = Asn1Element.Tag.ENUM) = decodeToLong(assertTag)


/** Exception-free version of [decodeToEnumOrdinal]*/
@Suppress("NOTHING_TO_INLINE")
inline fun Asn1Primitive.decodeToEnumOrdinalOrNull(assertTag: Asn1Element.Tag = Asn1Element.Tag.ENUM) =
    catchingUnwrapped { decodeToEnumOrdinal(assertTag) }.getOrNull()

/**
 * decodes this [Asn1Primitive]'s content into an enum Entry based on the decoded ordinal. [assertTag] defaults to [Asn1Element.Tag.ENUM], but can be
 * overridden (for implicitly tagged enums, for example).
 *
 * **Note that ASN.1 allows for negative ordinals and ordinals beyond 32 bit integers, exceeding Kotlin's enums!**
 * @throws [Asn1Exception] on invalid input
 */
@Throws(Asn1Exception::class)
inline fun <reified E : Enum<E>> Asn1Primitive.decodeToEnum(assertTag: Asn1Element.Tag = Asn1Element.Tag.ENUM): E =
    runRethrowing {
        val ordinal = decodeToEnumOrdinal(assertTag)
        require(ordinal >= 0) { "Negative ordinal $ordinal cannot be auto-mapped to an enum value" }
        require(ordinal <= Int.MAX_VALUE.toLong()) { "Ordinal $ordinal too large!" }
        enumEntries<E>().get(ordinal.toInt())
    }

/** Exception-free version of [decodeToEnum]*/
inline fun <reified E : Enum<E>> Asn1Primitive.decodeToEnumOrNull(assertTag: Asn1Element.Tag = Asn1Element.Tag.ENUM): E? =
    catchingUnwrapped { decodeToEnum<E>(assertTag) }.getOrNull()

/**
 * decodes this [Asn1Primitive]'s content into an [Int]. [assertTag] defaults to [Asn1Element.Tag.INT], but can be
 *  overridden (for implicitly tagged integers, for example)
 * @throws [Asn1Exception] on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.decodeToInt(assertTag: Asn1Element.Tag = Asn1Element.Tag.INT) =
    runRethrowing { decode(assertTag) { Int.decodeFromAsn1ContentBytes(it) } }

/** Exception-free version of [decodeToInt] */
fun Asn1Primitive.decodeToIntOrNull(assertTag: Asn1Element.Tag = Asn1Element.Tag.INT) =
    catchingUnwrapped { decodeToInt(assertTag) }.getOrNull()

/**
 * decodes this [Asn1Primitive]'s content into a [Long]. [assertTag] defaults to [Asn1Element.Tag.INT], but can be
 * overridden (for implicitly tagged longs, for example)
 * @throws [Asn1Exception] on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.decodeToLong(assertTag: Asn1Element.Tag = Asn1Element.Tag.INT) =
    runRethrowing { decode(assertTag) { Long.decodeFromAsn1ContentBytes(it) } }

/** Exception-free version of [decodeToLong] */
@Suppress("NOTHING_TO_INLINE")
inline fun Asn1Primitive.decodeToLongOrNull(assertTag: Asn1Element.Tag = Asn1Element.Tag.INT) =
    catchingUnwrapped { decodeToLong(assertTag) }.getOrNull()

/**
 * decodes this [Asn1Primitive]'s content into an [UInt]√. [assertTag] defaults to [Asn1Element.Tag.INT], but can be
 * overridden (for implicitly tagged unsigned integers, for example)
 * @throws [Asn1Exception] on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.decodeToUInt(assertTag: Asn1Element.Tag = Asn1Element.Tag.INT) =
    runRethrowing { decode(assertTag) { UInt.decodeFromAsn1ContentBytes(it) } }

/** Exception-free version of [decodeToUInt] */
@Suppress("NOTHING_TO_INLINE")
inline fun Asn1Primitive.decodeToUIntOrNull(assertTag: Asn1Element.Tag = Asn1Element.Tag.INT) =
    catchingUnwrapped { decodeToUInt(assertTag) }.getOrNull()

/**
 * decodes this [Asn1Primitive]'s content into an [ULong]. [assertTag] defaults to [Asn1Element.Tag.INT], but can be
 * overridden (for implicitly tagged unsigned longs, for example)
 * @throws [Asn1Exception] on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.decodeToULong(assertTag: Asn1Element.Tag = Asn1Element.Tag.INT) =
    runRethrowing { decode(assertTag) { ULong.decodeFromAsn1ContentBytes(it) } }

/** Exception-free version of [decodeToULong] */
@Suppress("NOTHING_TO_INLINE")
inline fun Asn1Primitive.decodeToULongOrNull(assertTag: Asn1Element.Tag = Asn1Element.Tag.INT) =
    catchingUnwrapped { decodeToULong(assertTag) }.getOrNull()

/** Decode the [Asn1Primitive] as an [Asn1Integer]
 * @throws [Asn1Exception] on invalid input */
@Throws(Asn1Exception::class)
fun Asn1Primitive.decodeToAsn1Integer(assertTag: Asn1Element.Tag = Asn1Element.Tag.INT) =
    runRethrowing { decode(assertTag) { Asn1Integer.decodeFromAsn1ContentBytes(it) } }

/** Exception-free version of [decodeToAsn1Integer] */
@Suppress("NOTHING_TO_INLINE")
inline fun Asn1Primitive.decodeToAsn1IntegerOrNull(assertTag: Asn1Element.Tag = Asn1Element.Tag.INT) =
    catchingUnwrapped { decodeToAsn1Integer() }.getOrNull()

/**
 * Decodes a [Asn1Integer] from [bytes] assuming the same encoding as the [Asn1Primitive.content] property of an [Asn1Primitive] containing an ASN.1 INTEGER
 */
@Throws(Asn1Exception::class)
fun Asn1Integer.Companion.decodeFromAsn1ContentBytes(bytes: ByteArray): Asn1Integer =
    runRethrowing { fromTwosComplement(bytes) }

/** Decode the [Asn1Primitive] as an [Asn1Real]
 * @throws [Asn1Exception] on invalid input*/
@Throws(Asn1Exception::class)
fun Asn1Primitive.decodeToAsn1Real(assertTag: Asn1Element.Tag = Asn1Element.Tag.REAL) =
    runRethrowing { decode(assertTag) { Asn1Real.decodeFromAsn1ContentBytes(it) } }

/** Exception-free version of [decodeToAsn1Real] */
@Suppress("NOTHING_TO_INLINE")
inline fun Asn1Primitive.decodeToAsn1RealOrNull(assertTag: Asn1Element.Tag = Asn1Element.Tag.REAL): Asn1Real? =
    catchingUnwrapped { decodeToAsn1Real(assertTag) }.getOrNull()

/** Decode the [Asn1Primitive] as a [Double]. **Beware of possible loss of precision!**
 * @throws [Asn1Exception] on invalid input*/
@Throws(Asn1Exception::class)
fun Asn1Primitive.decodeToDouble(assertTag: Asn1Element.Tag = Asn1Element.Tag.REAL) =
    decodeToAsn1Real(assertTag).toDouble()

/** Exception-free version of [decodeToDouble]. **Beware of possible loss of precision!** */
@Suppress("NOTHING_TO_INLINE")
inline fun Asn1Primitive.decodeToDoubleOrNull(assertTag: Asn1Element.Tag = Asn1Element.Tag.REAL) =
    catchingUnwrapped { decodeToDouble(assertTag) }.getOrNull()

/** Decode the [Asn1Primitive] as a [Float]. **Beware of *probable* loss of precision!**
 * @throws [Asn1Exception] on invalid input*/
@Throws(Asn1Exception::class)
@Suppress("NOTHING_TO_INLINE")
inline fun Asn1Primitive.decodeToFloat(assertTag: Asn1Element.Tag = Asn1Element.Tag.REAL) =
    decodeToAsn1Real(assertTag).toFloat()

/** Exception-free version of [decodeToFloat]. **Beware of *probable* loss of precision!** */
@Suppress("NOTHING_TO_INLINE")
inline fun Asn1Primitive.decodeToFloatOrNull(assertTag: Asn1Element.Tag = Asn1Element.Tag.REAL) =
    catchingUnwrapped { decodeToFloat(assertTag) }.getOrNull()


// If the implicit tag is used, the caller needs to call one of the methods for decoding to specific Asn1String type
fun Asn1Primitive.asAsn1String(): Asn1String = runRethrowing {
    when (tag.tagValue) {
        UTF8_STRING.toULong() -> Asn1String.UTF8(content)
        UNIVERSAL_STRING.toULong() -> Asn1String.Universal(content)
        IA5_STRING.toULong() -> Asn1String.IA5(content)
        BMP_STRING.toULong() -> Asn1String.BMP(content)
        T61_STRING.toULong() -> Asn1String.Teletex(content)
        PRINTABLE_STRING.toULong() -> Asn1String.Printable(content)
        NUMERIC_STRING.toULong() -> Asn1String.Numeric(content)
        VISIBLE_STRING.toULong() -> Asn1String.Visible(content)
        else -> throw Asn1StructuralException("Unsupported ASN.1 string tag $tag")
    }
}

/**
 * decodes this [Asn1Primitive]'s content into a [Asn1String.UTF8]. [assertTag] defaults to [Asn1Element.Tag.STRING_UTF8], but can be
 * overridden (for implicitly tagged strings, for example)
 * @throws [Asn1Exception] on invalid input
 */
@Throws(Asn1Exception::class)
inline fun Asn1Primitive.decodeToUtf8String(assertTag: Asn1Element.Tag = Asn1Element.Tag.STRING_UTF8) =
    runRethrowing { decode(assertTag) { Asn1String.UTF8(content) } }

/**
 * decodes this [Asn1Primitive]'s content into a [Asn1String.Universal]. [assertTag] defaults to [Asn1Element.Tag.STRING_UNIVERSAL], but can be
 * overridden (for implicitly tagged strings, for example)
 * @throws [Asn1Exception] on invalid input
 */
@Throws(Asn1Exception::class)
inline fun Asn1Primitive.decodeToUniversalString(assertTag: Asn1Element.Tag = Asn1Element.Tag.STRING_UNIVERSAL) =
    runRethrowing { decode(assertTag) { Asn1String.Universal(content) } }

/**
 * decodes this [Asn1Primitive]'s content into a [Asn1String.IA5]. [assertTag] defaults to [Asn1Element.Tag.STRING_IA5], but can be
 * overridden (for implicitly tagged strings, for example)
 * @throws [Asn1Exception] on invalid input
 */
@Throws(Asn1Exception::class)
inline fun Asn1Primitive.decodeToIa5String(assertTag: Asn1Element.Tag = Asn1Element.Tag.STRING_IA5) =
    runRethrowing { decode(assertTag) { Asn1String.IA5(content) } }

/**
 * decodes this [Asn1Primitive]'s content into a [Asn1String.BMP]. [assertTag] defaults to [Asn1Element.Tag.STRING_BMP], but can be
 * overridden (for implicitly tagged strings, for example)
 * @throws [Asn1Exception] on invalid input
 */
@Throws(Asn1Exception::class)
inline fun Asn1Primitive.decodeToBmpString(assertTag: Asn1Element.Tag = Asn1Element.Tag.STRING_BMP) =
    runRethrowing { decode(assertTag) { Asn1String.BMP(content) } }

/**
 * decodes this [Asn1Primitive]'s content into a [Asn1String.Teletex]. [assertTag] defaults to [Asn1Element.Tag.STRING_T61], but can be
 * overridden (for implicitly tagged strings, for example)
 * @throws [Asn1Exception] on invalid input
 */
@Throws(Asn1Exception::class)
inline fun Asn1Primitive.decodeToTeletextString(assertTag: Asn1Element.Tag = Asn1Element.Tag.STRING_T61) =
    runRethrowing { decode(assertTag) { Asn1String.Teletex(content) } }

/**
 * decodes this [Asn1Primitive]'s content into a [Asn1String.Printable]. [assertTag] defaults to [Asn1Element.Tag.STRING_PRINTABLE], but can be
 * overridden (for implicitly tagged strings, for example)
 * @throws [Asn1Exception] on invalid input
 */
@Throws(Asn1Exception::class)
inline fun Asn1Primitive.decodeToPrintableString(assertTag: Asn1Element.Tag = Asn1Element.Tag.STRING_PRINTABLE) =
    runRethrowing { decode(assertTag) { Asn1String.Printable(content) } }

/**
 * decodes this [Asn1Primitive]'s content into a [Asn1String.Numeric]. [assertTag] defaults to [Asn1Element.Tag.STRING_NUMERIC], but can be
 * overridden (for implicitly tagged strings, for example)
 * @throws [Asn1Exception] on invalid input
 */
@Throws(Asn1Exception::class)
inline fun Asn1Primitive.decodeToNumericString(assertTag: Asn1Element.Tag = Asn1Element.Tag.STRING_NUMERIC) =
    runRethrowing { decode(assertTag) { Asn1String.Numeric(content) } }

/**
 * decodes this [Asn1Primitive]'s content into a [Asn1String.Visible]. [assertTag] defaults to [Asn1Element.Tag.STRING_VISIBLE], but can be
 * overridden (for implicitly tagged strings, for example)
 * @throws [Asn1Exception] on invalid input
 */
@Throws(Asn1Exception::class)
inline fun Asn1Primitive.decodeToVisibleString(assertTag: Asn1Element.Tag = Asn1Element.Tag.STRING_VISIBLE) =
    runRethrowing { decode(assertTag) { Asn1String.Visible(content) } }

/**
 * decodes this [Asn1Primitive]'s content into a [Asn1String.General]. [assertTag] defaults to [Asn1Element.Tag.STRING_GENERAL], but can be
 * overridden (for implicitly tagged strings, for example)
 * @throws [Asn1Exception] on invalid input
 */
@Throws(Asn1Exception::class)
inline fun Asn1Primitive.decodeToGeneralString(assertTag: Asn1Element.Tag = Asn1Element.Tag.STRING_GENERAL) =
    runRethrowing { decode(assertTag) { Asn1String.General(content) } }

/**
 * decodes this [Asn1Primitive]'s content into a [Asn1String.Graphic]. [assertTag] defaults to [Asn1Element.Tag.STRING_GRAPHIC], but can be
 * overridden (for implicitly tagged strings, for example)
 * @throws [Asn1Exception] on invalid input
 */
@Throws(Asn1Exception::class)
inline fun Asn1Primitive.decodeToGraphicString(assertTag: Asn1Element.Tag = Asn1Element.Tag.STRING_GRAPHIC) =
    runRethrowing { decode(assertTag) { Asn1String.Graphic(content) } }

/**
 * decodes this [Asn1Primitive]'s content into a [Asn1String.Unrestricted]. [assertTag] defaults to [Asn1Element.Tag.STRING_UNRESTRICTED], but can be
 * overridden (for implicitly tagged strings, for example)
 * @throws [Asn1Exception] on invalid input
 */
@Throws(Asn1Exception::class)
inline fun Asn1Primitive.decodeToUnrestrictedString(assertTag: Asn1Element.Tag = Asn1Element.Tag.STRING_UNRESTRICTED) =
    runRethrowing { decode(assertTag) { Asn1String.Unrestricted(content) } }

/**
 * decodes this [Asn1Primitive]'s content into a [Asn1String.Videotex]. [assertTag] defaults to [Asn1Element.Tag.STRING_VIDEOTEX], but can be
 * overridden (for implicitly tagged strings, for example)
 * @throws [Asn1Exception] on invalid input
 */
@Throws(Asn1Exception::class)
inline fun Asn1Primitive.decodeToVideotexString(assertTag: Asn1Element.Tag = Asn1Element.Tag.STRING_VIDEOTEX) =
    runRethrowing { decode(assertTag) { Asn1String.Videotex(content) } }


/**
 * Decodes this [Asn1Primitive]'s content into a String.
 * @throws [Asn1Exception] all sorts of exceptions on invalid input
 */
fun Asn1Primitive.decodeToString() = runRethrowing { Asn1String.decodeFromTlv(this).value }

/** Exception-free version of [decodeToString] */
fun Asn1Primitive.decodeToStringOrNull() = catchingUnwrapped { decodeToString() }.getOrNull()

/**
 * decodes this [Asn1Primitive]'s content into an [Instant] if it is encoded as UTC TIME or GENERALIZED TIME
 *
 * @throws Asn1Exception on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.decodeToInstant() =
    when (tag) {
        Asn1Element.Tag.TIME_UTC -> decode(
            Asn1Element.Tag.TIME_UTC,
            Instant.Companion::decodeUtcTimeFromAsn1ContentBytes
        )

        Asn1Element.Tag.TIME_GENERALIZED -> decode(
            Asn1Element.Tag.TIME_GENERALIZED,
            Instant.Companion::decodeGeneralizedTimeFromAsn1ContentBytes
        )

        else -> throw Asn1StructuralException("Unsupported ASN.1 time tag $tag")
    }

/**
 * Exception-free version of [decodeToInstant]
 */
fun Asn1Primitive.decodeToInstantOrNull() = catchingUnwrapped { decodeToInstant() }.getOrNull()

/**
 * Transforms this [Asn1Primitive]' into an [Asn1BitString], assuming it was encoded as BIT STRING
 * @throws Asn1Exception  on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.asAsn1BitString(assertTag: Asn1Element.Tag =Asn1Element.Tag.BIT_STRING) = Asn1BitString.decodeFromTlv(this, assertTag)

/**
 * decodes this [Asn1Primitive] to null (i.e. verifies the tag to be [BERTags.ASN1_NULL] and the content to be empty
 *
 * @throws Asn1Exception  on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.readNull() = decode(Asn1Element.Tag.NULL) {}

/**
 * Name seems odd, but this is just an exception-free version of [readNull]
 */
fun Asn1Primitive.readNullOrNull() = catchingUnwrapped { readNull() }.getOrNull()

/**
 * Generic decoding function. Verifies that this [Asn1Primitive]'s tag matches [assertTag]
 * and transforms its content as per [transform]
 * @throws Asn1Exception all sorts of exceptions on invalid input
 */
@Throws(Asn1Exception::class)
inline fun <reified T> Asn1Primitive.decode(assertTag: ULong, transform: (content: ByteArray) -> T): T =
    decode(Asn1Element.Tag(assertTag, constructed = false), transform)

/**
 * Generic decoding function. Verifies that this [Asn1Primitive]'s tag matches [assertTag]
 * and transforms its content as per [transform]
 * @throws Asn1Exception all sorts of exceptions on invalid input
 */
@Throws(Asn1Exception::class)
inline fun <reified T> Asn1Primitive.decode(assertTag: Asn1Element.Tag, transform: (content: ByteArray) -> T) =
    runRethrowing {
        if (assertTag.isConstructed) throw IllegalArgumentException("A primitive cannot have a CONSTRUCTED tag")
        if (assertTag != this.tag) throw Asn1TagMismatchException(assertTag, this.tag)
        transform(content)
    }

/**
 * Exception-free version of [decode]
 */
inline fun <reified T> Asn1Primitive.decodeOrNull(tag: ULong, transform: (content: ByteArray) -> T) =
    catchingUnwrapped { decode(tag, transform) }.getOrNull()

/**
 * Decodes an [Instant] from the given content bytes assuming the same encoding as the [Asn1Primitive.content] property of an [Asn1Primitive] containing an ASN.1 UTC TIME
 * @throws Asn1Exception if the input does not parse
 */
@Throws(Asn1Exception::class)
fun Instant.Companion.decodeUtcTimeFromAsn1ContentBytes(input: ByteArray): Instant = runRethrowing {
    val s = input.decodeToString()
    if (s.length != 13) throw IllegalArgumentException("Input too short: $input")
    val year = "${s[0]}${s[1]}".toInt()
    val century = if (year <= 49) "20" else "19" // RFC 5280 4.1.2.5 Validity
    val isoString = "$century${s[0]}${s[1]}" + // year
            "-${s[2]}${s[3]}" + // month
            "-${s[4]}${s[5]}" + // day
            "T${s[6]}${s[7]}" + // hour
            ":${s[8]}${s[9]}" + // minute
            ":${s[10]}${s[11]}" + // seconds
            "${s[12]}" // time offset
    return parse(isoString)
}

/**
 * Decodes an [Instant] from the given content bytes assuming the same encoding as the [Asn1Primitive.content] property of an [Asn1Primitive] containing an ASN.1 GENERALIZED TIME
 * @throws Asn1Exception if the input does not parse
 */
@Throws(Asn1Exception::class)
fun Instant.Companion.decodeGeneralizedTimeFromAsn1ContentBytes(bytes: ByteArray): Instant = runRethrowing {
    val s = bytes.decodeToString()
    if (s.length != 15) throw IllegalArgumentException("Input too short: $bytes")
    val isoString = "${s[0]}${s[1]}${s[2]}${s[3]}" + // year
            "-${s[4]}${s[5]}" + // month
            "-${s[6]}${s[7]}" + // day
            "T${s[8]}${s[9]}" + // hour
            ":${s[10]}${s[11]}" + // minute
            ":${s[12]}${s[13]}" + // seconds
            "${s[14]}" // time offset
    return parse(isoString)
}

/**
 * Decodes a signed [Int] from [bytes] assuming the same encoding as the [Asn1Primitive.content] property of an [Asn1Primitive] containing an ASN.1 INTEGER
 * @throws Asn1Exception if the byte array is out of bounds for a signed int
 */
@Throws(Asn1Exception::class)
fun Int.Companion.decodeFromAsn1ContentBytes(bytes: ByteArray): Int =
    runRethrowing { fromTwosComplementByteArray(bytes) }

/**
 * Decodes a signed [Long] from [bytes] assuming the same encoding as the [Asn1Primitive.content] property of an [Asn1Primitive] containing an ASN.1 INTEGER
 * @throws Asn1Exception if the byte array is out of bounds for a signed long
 */
@Throws(Asn1Exception::class)
fun Long.Companion.decodeFromAsn1ContentBytes(bytes: ByteArray): Long =
    runRethrowing { fromTwosComplementByteArray(bytes) }

/**
 * Decodes a [UInt] from [bytes] assuming the same encoding as the [Asn1Primitive.content] property of an [Asn1Primitive] containing an ASN.1 INTEGER
 * @throws Asn1Exception if the byte array is out of bounds for an unsigned int
 */
@Throws(Asn1Exception::class)
fun UInt.Companion.decodeFromAsn1ContentBytes(bytes: ByteArray): UInt =
    runRethrowing { fromTwosComplementByteArray(bytes) }

/**
 * Decodes a [ULong] from [bytes] assuming the same encoding as the [Asn1Primitive.content] property of an [Asn1Primitive] containing an ASN.1 INTEGER
 * @throws Asn1Exception if the byte array is out of bounds for an unsigned long
 */
@Throws(Asn1Exception::class)
fun ULong.Companion.decodeFromAsn1ContentBytes(bytes: ByteArray): ULong =
    runRethrowing { fromTwosComplementByteArray(bytes) }

/**
 * Decodes a [Boolean] from [bytes] assuming the same encoding as the [Asn1Primitive.content] property of an [Asn1Primitive] containing an ASN.1 BOOLEAN
 */
fun Boolean.Companion.decodeFromAsn1ContentBytes(bytes: ByteArray): Boolean {
    if (bytes.size != 1) throw Asn1Exception("Not a Boolean!")
    return when (bytes.first().toUByte()) {
        0.toUByte() -> false
        //lenient boolean
        else -> true
        //else -> throw Asn1Exception("${bytes.first().toString(16).uppercase()} is not a boolean value!")
    }
}


/**
 * Decodes a [String] from [bytes] assuming the same encoding as the [Asn1Primitive.content] property of an [Asn1Primitive] containing an ASN.1 STRING (any kind)
 * The bytes are always decoded as UTF-8, via the standard library's [ByteArray.decodeToString]
 */
fun String.Companion.decodeFromAsn1ContentBytes(bytes: ByteArray) = bytes.decodeToString()


/**
 * Convenience method, directly DER-decoding a byte array to [T]
 * @throws Asn1Exception if invalid data is provided
 */
@Throws(Asn1Exception::class)
@OptIn(InternalAwesn1Api::class)
fun <A : Asn1Element, T : Asn1Encodable<A>> Asn1Decodable<A, T>.decodeFromDer(
    src: ByteArray,
    assertTag: Asn1Element.Tag? = null
): T =
    decodeFromDer(src.wrapInUnsafeSource(), assertTag)

/**
 * Exception-free version of [decodeFromDer]
 */
fun <A : Asn1Element, T : Asn1Encodable<A>> Asn1Decodable<A, T>.decodeFromDerOrNull(
    src: ByteArray,
    assertTag: Asn1Element.Tag? = null
) =
    catchingUnwrapped { decodeFromDer(src, assertTag) }.getOrNull()
