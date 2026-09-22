// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(InternalAwesn1Api::class)
@file:Suppress("SERIALIZER_TYPE_INCOMPATIBLE")

package at.asitplus.awesn1

import at.asitplus.awesn1.BERTags.BMP_STRING
import at.asitplus.awesn1.BERTags.GENERAL_STRING
import at.asitplus.awesn1.BERTags.GRAPHIC_STRING
import at.asitplus.awesn1.BERTags.IA5_STRING
import at.asitplus.awesn1.BERTags.NUMERIC_STRING
import at.asitplus.awesn1.BERTags.PRINTABLE_STRING
import at.asitplus.awesn1.BERTags.T61_STRING
import at.asitplus.awesn1.BERTags.UNIVERSAL_STRING
import at.asitplus.awesn1.BERTags.UNRESTRICTED_STRING
import at.asitplus.awesn1.BERTags.UTF8_STRING
import at.asitplus.awesn1.BERTags.VIDEOTEX_STRING
import at.asitplus.awesn1.BERTags.VISIBLE_STRING
import at.asitplus.awesn1.encoding.decodeFromAsn1ContentBytes
import at.asitplus.awesn1.encoding.decodeToBmpString
import at.asitplus.awesn1.encoding.decodeToGeneralString
import at.asitplus.awesn1.encoding.decodeToGraphicString
import at.asitplus.awesn1.encoding.decodeToIa5String
import at.asitplus.awesn1.encoding.decodeToNumericString
import at.asitplus.awesn1.encoding.decodeToPrintableString
import at.asitplus.awesn1.encoding.decodeToTeletextString
import at.asitplus.awesn1.encoding.decodeToUniversalString
import at.asitplus.awesn1.encoding.decodeToUnrestrictedString
import at.asitplus.awesn1.encoding.decodeToUtf8String
import at.asitplus.awesn1.encoding.decodeToVideotexString
import at.asitplus.awesn1.encoding.decodeToVisibleString
import at.asitplus.awesn1.encoding.decodeFromDer
import at.asitplus.awesn1.encoding.encodeToDer
import at.asitplus.awesn1.serialization.Asn1DerDecoder
import at.asitplus.awesn1.serialization.Asn1DerEncoder
import at.asitplus.awesn1.serialization.Asn1Serializable
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

private fun decodeTeletexContent(bytes: ByteArray): String =
    CharArray(bytes.size) { (bytes[it].toInt() and 0xff).toChar() }.concatToString()

private fun encodeTeletexContent(value: String): ByteArray {
    val result = ByteArray(value.length)
    value.forEachIndexed { index, char ->
        if (char.code > 0xff) throw Asn1Exception("T61String cannot represent U+${char.code.toString(16).uppercase()}")
        result[index] = char.code.toByte()
    }
    return result
}

private fun decodeBmpContent(bytes: ByteArray): String {
    if (bytes.size % 2 != 0) throw Asn1Exception("BMPString content length must be divisible by 2")
    return CharArray(bytes.size / 2) { i ->
        val o = i * 2
        val v = ((bytes[o].toInt() and 0xff) shl 8) or (bytes[o + 1].toInt() and 0xff)
        if (v in 0xd800..0xdfff) throw Asn1Exception("BMPString contains surrogate U+${v.toString(16)}")
        v.toChar()
    }.concatToString()
}

private fun encodeBmpContent(value: String): ByteArray {
    if (value.length > Int.MAX_VALUE / 2) throw Asn1Exception("BMPString is too large")
    val result = ByteArray(value.length * 2)
    value.forEachIndexed { i, c ->
        if (c in '\uD800'..'\uDFFF') throw Asn1Exception("BMPString cannot contain surrogate code units")
        result[i * 2] = (c.code ushr 8).toByte()
        result[i * 2 + 1] = c.code.toByte()
    }
    return result
}

private fun decodeUniversalContent(bytes: ByteArray): String {
    if (bytes.size % 4 != 0) throw Asn1Exception("UniversalString content length must be divisible by 4")
    val result = StringBuilder(bytes.size / 4)
    for (o in bytes.indices step 4) {
        val cp = ((bytes[o].toLong() and 0xff) shl 24) or ((bytes[o + 1].toLong() and 0xff) shl 16) or
            ((bytes[o + 2].toLong() and 0xff) shl 8) or (bytes[o + 3].toLong() and 0xff)
        if (cp > 0x10ffffL || cp in 0xd800L..0xdfffL) throw Asn1Exception("Invalid UniversalString code point U+${cp.toString(16)}")
        if (cp <= 0xffff) result.append(cp.toInt().toChar()) else {
            val s = cp.toInt() - 0x10000
            result.append((0xd800 + (s ushr 10)).toChar())
            result.append((0xdc00 + (s and 0x3ff)).toChar())
        }
    }
    return result.toString()
}

private fun encodeUniversalContent(value: String): ByteArray {
    if (value.length > Int.MAX_VALUE / 4) throw Asn1Exception("UniversalString is too large")
    var count = 0
    var i = 0
    while (i < value.length) {
        val c = value[i]
        if (c in '\uD800'..'\uDBFF') {
            if (i + 1 >= value.length || value[i + 1] !in '\uDC00'..'\uDFFF') throw Asn1Exception("Unpaired high surrogate in UniversalString")
            i += 2
        } else {
            if (c in '\uDC00'..'\uDFFF') throw Asn1Exception("Unpaired low surrogate in UniversalString")
            i++
        }
        count++
    }
    if (count > Int.MAX_VALUE / 4) throw Asn1Exception("UniversalString is too large")
    val result = ByteArray(count * 4)
    i = 0
    var o = 0
    while (i < value.length) {
        val c = value[i]
        val cp = if (c in '\uD800'..'\uDBFF') {
            val low = value[i + 1]
            i += 2
            0x10000 + ((c.code - 0xd800) shl 10) + (low.code - 0xdc00)
        } else { i++; c.code }
        result[o] = (cp ushr 24).toByte(); result[o + 1] = (cp ushr 16).toByte()
        result[o + 2] = (cp ushr 8).toByte(); result[o + 3] = cp.toByte(); o += 4
    }
    return result
}


/**
 * ASN.1 String class used as wrapper do discriminate between different ASN.1 string types
 * By default, the string value is decoded using UTF-8. If a different charset or custom decoding
 * is needed, the [rawValue] property can be used directly.
 *
 * Under DER serialization with `awesn1.kxs`, generic [Asn1String] values are decoded by their
 * universal ASN.1 string tag. This means generic [Asn1String] must not be used together with
 * implicit tag overrides such as `@Asn1Tag`, because the concrete string subtype would no longer
 * be recoverable from the wire representation. Use a concrete subtype like [UTF8], [IA5],
 * [Printable], [Visible], or [Numeric] when implicit tagging is required.
 *
 * String values are internally represented as raw [ByteArray]. Wide-character subtypes validate their
 * mandated encodings when constructed or typed-decoded; malformed bytes can still be retained in raw
 * [Asn1Element] values. The [isValid] property reports validity for the concrete type.
 */
@Serializable(with = Asn1String.Companion::class)
sealed class Asn1String(
    val rawValue: ByteArray,
    val performValidation: Boolean
) : Asn1Encodable<Asn1Primitive> {
    abstract val tag: ULong

    /**
     * The UTF-8 interpretation of [rawValue] by default; wide-character subtypes override this.
     * The decoding is performed via `String.decodeFromAsn1ContentBytes(rawValue)`, which internally uses
     * the standard library's [ByteArray.decodeToString].
     */
    open val value: String by lazy { String.decodeFromAsn1ContentBytes(rawValue) }

    /**
     * Returns whether this string's [rawValue] is valid for its concrete ASN.1 string type:
     * - `true`: validation succeeded
     * - `false`: validation failed
     * - `null`: no validation implemented (see [Unrestricted], [Videotex])
     *
     * With the sole exception of [UTF8] (which validates the raw UTF-8 bytes directly), validation is evaluated
     * against the decoded [value].
     *
     * **Accuracy caveat:** [Teletex], [General], and [Graphic] cannot be validated exactly (their true repertoires
     * are multi-byte / ISO 2022). They perform *best-effort* recognition: `true` for a recognized subset, `null`
     * for anything else, and **never `false`** — so they never reject potentially-valid input. [UTF8], [IA5],
     * [Visible], [Printable], and [Numeric] validate their exact repertoires and do report `false` for violations.
     */
    abstract val isValid: Boolean?


    /**
     * UTF8 STRING (ISO/IEC 10646, encoded as UTF-8 per RFC 3629).
     *
     * [isValid] reports whether [rawValue] is **well-formed UTF-8**; it deliberately does *not* reject the
     * legitimate replacement character U+FFFD.
     */
    @Serializable(with = Asn1Utf8StringSerializer::class)
    class UTF8 private constructor(
        rawValue: ByteArray,
        performValidation: Boolean
    ) : Asn1String(rawValue, performValidation) {
        override val tag = BERTags.UTF8_STRING.toULong()

        /**
         * `true` iff [rawValue] is well-formed UTF-8, via a canonical round-trip: [value] decodes [rawValue]
         * (replacing any malformed sequence with U+FFFD), and re-encoding reproduces [rawValue] exactly **iff**
         * the input was well-formed. Bytes that genuinely encode U+FFFD round-trip and are reported valid;
         * malformed/overlong sequences re-encode differently and are reported invalid.
         *
         * **Limitation:** the [String] constructor cannot observe malformed bytes (any Kotlin [String] is
         * encodable), so it never rejects; byte-level validation is meaningful only for values decoded from ASN.1.
         */
        override val isValid: Boolean by lazy {
            value.encodeToByteArray().contentEquals(rawValue)
        }

        /**
         * @throws Asn1Exception if illegal characters are provided
         */
        @Throws(Asn1Exception::class)
        constructor(value: String) : this(value.encodeToByteArray(), true) {
            var i = 0
            while (i < value.length) {
                val c = value[i]
                if (c in '\uD800'..'\uDBFF') {
                    if (i + 1 >= value.length || value[i + 1] !in '\uDC00'..'\uDFFF') throw Asn1Exception("Unpaired high surrogate in UTF8 string")
                    i += 2
                } else {
                    if (c in '\uDC00'..'\uDFFF') throw Asn1Exception("Unpaired low surrogate in UTF8 string")
                    i++
                }
            }
            if (!isValid) throw Asn1Exception("Input contains invalid chars: '$value'")
        }

        @PublishedApi
        internal constructor(rawValue: ByteArray) : this(rawValue, false)
    }

    /**
     * UNIVERSAL STRING, encoded as big-endian 32-bit Unicode scalar values.
     */
    @Serializable(with = Asn1StringSerializer::class)
    class Universal private constructor(
        rawValue: ByteArray,
        performValidation: Boolean
    ) : Asn1String(rawValue, performValidation) {
        override val tag = BERTags.UNIVERSAL_STRING.toULong()

        override val value: String by lazy { decodeUniversalContent(rawValue) }
        override val isValid: Boolean by lazy { runCatching { decodeUniversalContent(rawValue) }.isSuccess }

        constructor(value: String) : this(encodeUniversalContent(value), true)

        @PublishedApi
        internal constructor(rawValue: ByteArray) : this(rawValue, false) {
            decodeUniversalContent(rawValue)
        }
    }

    /**
     * VISIBLE STRING (a.k.a. ISO646String).
     *
     * The visible/printing subset of ITU-T T.50: graphic characters plus SPACE, i.e. `0x20`–`0x7E`
     * (no control characters, no DELETE).
     */
    @Serializable(with = Asn1VisibleStringSerializer::class)
    class Visible private constructor(
        rawValue: ByteArray,
        performValidation: Boolean
    ) : Asn1String(rawValue, performValidation) {
        override val tag = BERTags.VISIBLE_STRING.toULong()

        override val isValid: Boolean by lazy {
            Regex("[\\x20-\\x7E]*").matches(value)
        }

        /**
         * @throws Asn1Exception if illegal characters are provided
         */
        @Throws(Asn1Exception::class)
        constructor(value: String) : this(value.encodeToByteArray(), true) {
            if (!isValid) throw Asn1Exception("Input contains invalid chars: '$value'")
        }

        @PublishedApi
        internal constructor(rawValue: ByteArray) : this(rawValue, false)
    }

    /**
     * IA5 STRING.
     *
     * The IA5 alphabet is the International Reference Alphabet (ITU-T T.50 / ISO 646): the full 7-bit range
     * `0x00`–`0x7F`, **including DELETE (`0x7F`)**. [isValid] accepts every code point `<= 0x7F`.
     */
    @Serializable(with = Asn1Ia5StringSerializer::class)
    class IA5 private constructor(
        rawValue: ByteArray,
        performValidation: Boolean
    ) : Asn1String(rawValue, performValidation) {
        override val tag = BERTags.IA5_STRING.toULong()

        /** `true` iff every character of [value] is in the 7-bit IA5 range `0x00`–`0x7F`. */
        override val isValid: Boolean by lazy {
            Regex("[\\x00-\\x7F]*").matches(value)
        }

        /**
         * @throws Asn1Exception if illegal characters are provided
         */
        @Throws(Asn1Exception::class)
        constructor(value: String) : this(value.encodeToByteArray(), true) {
            if (!isValid) throw Asn1Exception("Input contains invalid chars: '$value'")
        }

        @PublishedApi
        internal constructor(rawValue: ByteArray) : this(rawValue, false)
    }

    /**
     * TELETEX (T61) STRING.
     *
     * Deprecated for HTTPS certificates; prefer UTF-8 (see [Asn1String.UTF8]).
     *
     * awesn1 follows the BoringSSL/OpenSSL compatibility interpretation: every octet is one Latin-1 code point.
     * This is intentionally not a stateful implementation of the full ITU-T T.61 repertoire.
     */
    @Serializable(with = Asn1StringSerializer::class)
    class Teletex private constructor(
        rawValue: ByteArray,
        performValidation: Boolean
    ) : Asn1String(rawValue, performValidation) {
        override val tag = BERTags.T61_STRING.toULong()

        override val value: String by lazy { decodeTeletexContent(rawValue) }
        override val isValid: Boolean = true

        /**
         * @throws Asn1Exception if illegal characters are provided
         */
        @Throws(Asn1Exception::class)
        constructor(value: String) : this(encodeTeletexContent(value), true)

        @PublishedApi
        internal constructor(rawValue: ByteArray) : this(rawValue, false)
    }

    /**
     * BMP STRING, encoded as big-endian UCS-2 (surrogate code units are forbidden).
     */
    @Serializable(with = Asn1StringSerializer::class)
    class BMP private constructor(
        rawValue: ByteArray,
        performValidation: Boolean
    ) : Asn1String(rawValue, performValidation) {
        override val tag = BERTags.BMP_STRING.toULong()

        override val value: String by lazy { decodeBmpContent(rawValue) }
        override val isValid: Boolean by lazy { runCatching { decodeBmpContent(rawValue) }.isSuccess }

        constructor(value: String) : this(encodeBmpContent(value), true)

        @PublishedApi
        internal constructor(rawValue: ByteArray) : this(rawValue, false) {
            decodeBmpContent(rawValue)
        }
    }

    /**
     * GENERAL STRING.
     *
     * GeneralString (X.680 §41) comprises all registered ISO 2022 graphic (G) and control (C) sets plus SPACE and
     * DELETE — effectively unbounded, including 8-bit and multi-byte content.
     *
     * **Best-effort validation.** awesn1 does not model the full ISO 2022 repertoire. [isValid] only *recognizes*
     * the 7-bit subset (`0x00`–`0x7F`, which includes DELETE): it returns `true` for recognized content and `null`
     * ("unknown") otherwise, and **never returns `false`** — so it never rejects potentially-valid 8-bit or
     * multi-byte input, and the `String` constructor never throws.
     */
    @Serializable(with = Asn1StringSerializer::class)
    class General private constructor(
        rawValue: ByteArray,
        performValidation: Boolean
    ) : Asn1String(rawValue, performValidation) {
        override val tag = BERTags.GENERAL_STRING.toULong()

        override val isValid: Boolean? by lazy {
            if (Regex("[\\x00-\\x7F]*").matches(value)) true else null
        }

        /**
         * @throws Asn1Exception if illegal characters are provided
         */
        @Throws(Asn1Exception::class)
        constructor(value: String) : this(value.encodeToByteArray(), true) {
            if (isValid == false) throw Asn1Exception("Input contains invalid chars: '$value'")
        }

        @PublishedApi
        internal constructor(rawValue: ByteArray) : this(rawValue, false)
    }

    /**
     * GRAPHIC STRING.
     *
     * GraphicString (X.680 §41) comprises all registered ISO 2022 graphic (G) sets plus SPACE (no control
     * characters, no DELETE).
     *
     * **Best-effort validation.** awesn1 does not model the full ISO 2022 repertoire. [isValid] only *recognizes*
     * the 7-bit graphic subset (`0x20`–`0x7E`): it returns `true` for recognized content and `null` ("unknown")
     * otherwise, and **never returns `false`** — so it never rejects potentially-valid input such as accented
     * Latin-1 letters or CJK characters, and the `String` constructor never throws.
     */
    @Serializable(with = Asn1StringSerializer::class)
    class Graphic private constructor(
        rawValue: ByteArray,
        performValidation: Boolean
    ) : Asn1String(rawValue, performValidation) {
        override val tag = BERTags.GRAPHIC_STRING.toULong()

        override val isValid: Boolean? by lazy {
            if (Regex("[\\x20-\\x7E]*").matches(value)) true else null
        }

        /**
         * @throws Asn1Exception if illegal characters are provided
         */
        @Throws(Asn1Exception::class)
        constructor(value: String) : this(value.encodeToByteArray(), true) {
            if (isValid == false) throw Asn1Exception("Input contains invalid chars: '$value'")
        }

        @PublishedApi
        internal constructor(rawValue: ByteArray) : this(rawValue, false)
    }

    /**
     * CHARACTER/UNRESTRICTED STRING (no checks)
     */
    @Serializable(with = Asn1StringSerializer::class)
    class Unrestricted private constructor(
        rawValue: ByteArray,
        performValidation: Boolean
    ) : Asn1String(rawValue, performValidation) {
        override val tag = BERTags.UNRESTRICTED_STRING.toULong()

        /**
         * Always `null`, since no validation logic is implemented
         */
        override val isValid: Boolean? = null

        constructor(value: String) : this(value.encodeToByteArray(), false)

        @PublishedApi
        internal constructor(rawValue: ByteArray) : this(rawValue, false)
    }

    /**
     * VIDEOTEX STRING (no checks)
     * Validation is not implemented. This type is no longer used in practice.
     */
    @Serializable(with = Asn1StringSerializer::class)
    class Videotex private constructor(
        rawValue: ByteArray,
        performValidation: Boolean
    ) : Asn1String(rawValue, performValidation) {
        override val tag = BERTags.VIDEOTEX_STRING.toULong()

        /**
         * Always `null`, since no validation logic is implemented
         */
        override val isValid: Boolean? = null

        constructor(value: String) : this(value.encodeToByteArray(), false)

        @PublishedApi
        internal constructor(rawValue: ByteArray) : this(rawValue, false)
    }

    /**
     * PRINTABLE STRING.
     *
     * The PrintableString repertoire (X.680 §41): `A`–`Z`, `a`–`z`, `0`–`9`, SPACE and `' ( ) + , - . / : = ?`.
     */
    @Serializable(with = Asn1PrintableStringSerializer::class)
    class Printable private constructor(
        rawValue: ByteArray,
        performValidation: Boolean
    ) : Asn1String(rawValue, performValidation) {
        override val tag = BERTags.PRINTABLE_STRING.toULong()

        override val isValid: Boolean by lazy {
            Regex("[a-zA-Z0-9 '()+,-./:=?]*").matches(value)
        }

        /**
         * @throws Asn1Exception if illegal characters are provided
         */
        @Throws(Asn1Exception::class)
        constructor(value: String) : this(value.encodeToByteArray(), true) {
            if (!isValid) throw Asn1Exception("Input contains invalid chars: '$value'")
        }

        @PublishedApi
        internal constructor(rawValue: ByteArray) : this(rawValue, false)
    }

    /**
     * NUMERIC STRING.
     *
     * The NumericString repertoire (X.680 §41): digits `0`–`9` and SPACE.
     */
    @Serializable(with = Asn1NumericStringSerializer::class)
    class Numeric private constructor(
        rawValue: ByteArray,
        performValidation: Boolean
    ) : Asn1String(rawValue, performValidation) {
        override val tag = BERTags.NUMERIC_STRING.toULong()

        override val isValid: Boolean by lazy {
            Regex("[0-9 ]*").matches(value)
        }

        /**
         * @throws Asn1Exception if illegal characters are provided
         */
        @Throws(Asn1Exception::class)
        constructor(value: String) : this(value.encodeToByteArray(), true) {
            if (!isValid) throw Asn1Exception("Input contains invalid chars: '$value'")
        }

        @PublishedApi
        internal constructor(rawValue: ByteArray) : this(rawValue, false)
    }

    override fun encodeToTlv() = Asn1Primitive(tag, rawValue)
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Asn1String

        if (tag != other.tag) return false
        if (value != other.value) return false

        return true
    }

    override fun hashCode(): Int {
        var result = tag.hashCode()
        result = 31 * result + value.hashCode()
        return result
    }

    companion object : Asn1Serializable<Asn1Primitive, Asn1String>, StringFallbackSerializer<Asn1String> {
        override val leadingTags: Set<Asn1Element.Tag> = setOf(
            Asn1Element.Tag.STRING_UTF8,
            Asn1Element.Tag.STRING_UNIVERSAL,
            Asn1Element.Tag.STRING_IA5,
            Asn1Element.Tag.STRING_BMP,
            Asn1Element.Tag.STRING_T61,
            Asn1Element.Tag.STRING_PRINTABLE,
            Asn1Element.Tag.STRING_NUMERIC,
            Asn1Element.Tag.STRING_VISIBLE,
            Asn1Element.Tag.STRING_GENERAL,
            Asn1Element.Tag.STRING_GRAPHIC,
            Asn1Element.Tag.STRING_UNRESTRICTED,
            Asn1Element.Tag.STRING_VIDEOTEX,
        )

        override val descriptor: SerialDescriptor =
            PrimitiveSerialDescriptor(ASN1_DESCRIPTOR_STRING, PrimitiveKind.STRING)

        /**
         * Decodes an [Asn1Primitive] into a specific [Asn1String] subtype based on its tag.
         *
         * This generic decoder requires the universal ASN.1 string tag to stay visible. If the
         * value was implicitly tagged, decode it through a concrete subtype decoder such as
         * [decodeToUtf8String], [decodeToPrintableString], or another specific string decoder.
         *
         * @param src the ASN.1 primitive to decode
         * @return the corresponding [Asn1String] subtype
         * @throws Asn1Exception if decoding fails or the tag is unsupported
         */
        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Primitive): Asn1String = runRethrowing {
            when (src.tag.tagValue) {
                UTF8_STRING.toULong() -> src.decodeToUtf8String()
                UNIVERSAL_STRING.toULong() -> src.decodeToUniversalString()
                IA5_STRING.toULong() -> src.decodeToIa5String()
                BMP_STRING.toULong() -> src.decodeToBmpString()
                T61_STRING.toULong() -> src.decodeToTeletextString()
                PRINTABLE_STRING.toULong() -> src.decodeToPrintableString()
                NUMERIC_STRING.toULong() -> src.decodeToNumericString()
                VISIBLE_STRING.toULong() -> src.decodeToVisibleString()
                GENERAL_STRING.toULong() -> src.decodeToGeneralString()
                GRAPHIC_STRING.toULong() -> src.decodeToGraphicString()
                UNRESTRICTED_STRING.toULong() -> src.decodeToUnrestrictedString()
                VIDEOTEX_STRING.toULong() -> src.decodeToVideotexString()
                else -> throw Asn1Exception("Not an Asn1String!")
            }
        }

        override fun serialize(encoder: Encoder, value: Asn1String) {
            if (encoder is Asn1DerEncoder) encoder.encodeSerializableValue(ByteArraySerializer(), value.encodeToDer())
            else serializeFallback(encoder, value)
        }

        override fun decodeFallback(encoded: String): Asn1String = Asn1String.UTF8(encoded)

        override fun encodeFallback(value: Asn1String): String = value.value

        override fun deserialize(decoder: Decoder): Asn1String =
            if (decoder is Asn1DerDecoder) {
                ByteArraySerializer().deserialize(decoder).let { decodeFromDer(it) }
            } else {
                deserializeFallback(decoder)
            }

    }
}

/**
 * String serializer for [Asn1String] used for interoperability with non-DER serialization formats.
 *
 * When used with the `awesn1.kxs` DER format, this serializer is bypassed and the concrete ASN.1 string subtype is
 * encoded/decoded using proper DER TLV.
 */
internal object Asn1StringSerializer : KSerializer<Asn1String> by Asn1String.Companion

private inline fun <T : Asn1String> decodeImplicitlyTaggedAsn1StringSubtype(
    src: Asn1Primitive,
    assertTag: Asn1Element.Tag?,
    semanticTag: Asn1Element.Tag,
    decodeWithSemanticTag: (Asn1Primitive) -> T,
    decodeImplicitContent: (ByteArray) -> T,
): T {
    if (assertTag != null && src.tag != assertTag) {
        throw Asn1TagMismatchException(assertTag, src.tag)
    }
    return if (src.tag == semanticTag) {
        decodeWithSemanticTag(src)
    } else {
        decodeImplicitContent(src.content)
    }
}

object Asn1Utf8StringSerializer : Asn1Serializable<Asn1Primitive, Asn1String.UTF8>,
    StringFallbackSerializer<Asn1String.UTF8> {
    override val leadingTags: Set<Asn1Element.Tag> = setOf(Asn1Element.Tag.STRING_UTF8)
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor(ASN1_DESCRIPTOR_STRING, PrimitiveKind.STRING)

    override fun decodeFromTlv(src: Asn1Primitive, assertTag: Asn1Element.Tag?): Asn1String.UTF8 =
        decodeImplicitlyTaggedAsn1StringSubtype(
            src,
            assertTag,
            Asn1Element.Tag.STRING_UTF8,
            decodeWithSemanticTag = { it.decodeToUtf8String() },
            decodeImplicitContent = { Asn1String.UTF8(String.decodeFromAsn1ContentBytes(it)) },
        )

    override fun doDecode(src: Asn1Primitive): Asn1String.UTF8 = src.decodeToUtf8String()

    override fun serialize(encoder: Encoder, value: Asn1String.UTF8) {
        if (encoder is Asn1DerEncoder) encoder.encodeSerializableValue(ByteArraySerializer(), value.encodeToDer())
        else serializeFallback(encoder, value)
    }

    override fun decodeFallback(encoded: String): Asn1String.UTF8 = Asn1String.UTF8(encoded)

    override fun encodeFallback(value: Asn1String.UTF8): String = value.value

    override fun deserialize(decoder: Decoder): Asn1String.UTF8 =
        if (decoder is Asn1DerDecoder) ByteArraySerializer().deserialize(decoder).let { decodeFromDer(it) }
        else deserializeFallback(decoder)
}

object Asn1VisibleStringSerializer : Asn1Serializable<Asn1Primitive, Asn1String.Visible>,
    StringFallbackSerializer<Asn1String.Visible> {
    override val leadingTags: Set<Asn1Element.Tag> = setOf(Asn1Element.Tag.STRING_VISIBLE)
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor(ASN1_DESCRIPTOR_STRING, PrimitiveKind.STRING)

    override fun decodeFromTlv(src: Asn1Primitive, assertTag: Asn1Element.Tag?): Asn1String.Visible =
        decodeImplicitlyTaggedAsn1StringSubtype(
            src,
            assertTag,
            Asn1Element.Tag.STRING_VISIBLE,
            decodeWithSemanticTag = { it.decodeToVisibleString() },
            decodeImplicitContent = { Asn1String.Visible(String.decodeFromAsn1ContentBytes(it)) },
        )

    override fun doDecode(src: Asn1Primitive): Asn1String.Visible = src.decodeToVisibleString()

    override fun serialize(encoder: Encoder, value: Asn1String.Visible) {
        if (encoder is Asn1DerEncoder) encoder.encodeSerializableValue(ByteArraySerializer(), value.encodeToDer())
        else serializeFallback(encoder, value)
    }

    override fun decodeFallback(encoded: String): Asn1String.Visible = Asn1String.Visible(encoded)

    override fun encodeFallback(value: Asn1String.Visible): String = value.value

    override fun deserialize(decoder: Decoder): Asn1String.Visible =
        if (decoder is Asn1DerDecoder) ByteArraySerializer().deserialize(decoder).let { decodeFromDer(it) }
        else deserializeFallback(decoder)
}

object Asn1Ia5StringSerializer : Asn1Serializable<Asn1Primitive, Asn1String.IA5>,
    StringFallbackSerializer<Asn1String.IA5> {
    override val leadingTags: Set<Asn1Element.Tag> = setOf(Asn1Element.Tag.STRING_IA5)
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor(ASN1_DESCRIPTOR_STRING, PrimitiveKind.STRING)

    override fun decodeFromTlv(src: Asn1Primitive, assertTag: Asn1Element.Tag?): Asn1String.IA5 =
        decodeImplicitlyTaggedAsn1StringSubtype(
            src,
            assertTag,
            Asn1Element.Tag.STRING_IA5,
            decodeWithSemanticTag = { it.decodeToIa5String() },
            decodeImplicitContent = { Asn1String.IA5(it) },
        )

    override fun doDecode(src: Asn1Primitive): Asn1String.IA5 = src.decodeToIa5String()

    override fun serialize(encoder: Encoder, value: Asn1String.IA5) {
        if (encoder is Asn1DerEncoder) encoder.encodeSerializableValue(ByteArraySerializer(), value.encodeToDer())
        else serializeFallback(encoder, value)
    }

    override fun decodeFallback(encoded: String): Asn1String.IA5 = Asn1String.IA5(encoded)

    override fun encodeFallback(value: Asn1String.IA5): String = value.value

    override fun deserialize(decoder: Decoder): Asn1String.IA5 =
        if (decoder is Asn1DerDecoder) ByteArraySerializer().deserialize(decoder).let { decodeFromDer(it) }
        else deserializeFallback(decoder)
}

object Asn1PrintableStringSerializer : Asn1Serializable<Asn1Primitive, Asn1String.Printable>,
    StringFallbackSerializer<Asn1String.Printable> {
    override val leadingTags: Set<Asn1Element.Tag> = setOf(Asn1Element.Tag.STRING_PRINTABLE)
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor(ASN1_DESCRIPTOR_STRING, PrimitiveKind.STRING)

    override fun decodeFromTlv(src: Asn1Primitive, assertTag: Asn1Element.Tag?): Asn1String.Printable =
        decodeImplicitlyTaggedAsn1StringSubtype(
            src,
            assertTag,
            Asn1Element.Tag.STRING_PRINTABLE,
            decodeWithSemanticTag = { it.decodeToPrintableString() },
            decodeImplicitContent = { Asn1String.Printable(String.decodeFromAsn1ContentBytes(it)) },
        )

    override fun doDecode(src: Asn1Primitive): Asn1String.Printable = src.decodeToPrintableString()

    override fun serialize(encoder: Encoder, value: Asn1String.Printable) {
        if (encoder is Asn1DerEncoder) encoder.encodeSerializableValue(ByteArraySerializer(), value.encodeToDer())
        else serializeFallback(encoder, value)
    }

    override fun decodeFallback(encoded: String): Asn1String.Printable = Asn1String.Printable(encoded)

    override fun encodeFallback(value: Asn1String.Printable): String = value.value

    override fun deserialize(decoder: Decoder): Asn1String.Printable =
        if (decoder is Asn1DerDecoder) ByteArraySerializer().deserialize(decoder).let { decodeFromDer(it) }
        else deserializeFallback(decoder)
}

object Asn1NumericStringSerializer : Asn1Serializable<Asn1Primitive, Asn1String.Numeric>,
    StringFallbackSerializer<Asn1String.Numeric> {
    override val leadingTags: Set<Asn1Element.Tag> = setOf(Asn1Element.Tag.STRING_NUMERIC)
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor(ASN1_DESCRIPTOR_STRING, PrimitiveKind.STRING)

    override fun decodeFromTlv(src: Asn1Primitive, assertTag: Asn1Element.Tag?): Asn1String.Numeric =
        decodeImplicitlyTaggedAsn1StringSubtype(
            src,
            assertTag,
            Asn1Element.Tag.STRING_NUMERIC,
            decodeWithSemanticTag = { it.decodeToNumericString() },
            decodeImplicitContent = { Asn1String.Numeric(String.decodeFromAsn1ContentBytes(it)) },
        )

    override fun doDecode(src: Asn1Primitive): Asn1String.Numeric = src.decodeToNumericString()

    override fun serialize(encoder: Encoder, value: Asn1String.Numeric) {
        if (encoder is Asn1DerEncoder) encoder.encodeSerializableValue(ByteArraySerializer(), value.encodeToDer())
        else serializeFallback(encoder, value)
    }

    override fun decodeFallback(encoded: String): Asn1String.Numeric = Asn1String.Numeric(encoded)

    override fun encodeFallback(value: Asn1String.Numeric): String = value.value

    override fun deserialize(decoder: Decoder): Asn1String.Numeric =
        if (decoder is Asn1DerDecoder) ByteArraySerializer().deserialize(decoder).let { decodeFromDer(it) }
        else deserializeFallback(decoder)
}
