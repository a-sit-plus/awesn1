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
 * To enable parsing of non-compliant strings without exploding, every String is internally represented
 * as raw [ByteArray] and not validated during decoding from ASN.1.
 * The [isValid] property indicates whether the bytes contained in an ASN.1 String object type are valid
 * according to the validation rules of that type.
 */
@Serializable(with = Asn1String.Companion::class)
sealed class Asn1String(
    val rawValue: ByteArray,
    val performValidation: Boolean
) : Asn1Encodable<Asn1Primitive> {
    abstract val tag: ULong

    /**
     * Always the UTF-8 interpretation of [rawValue].
     * The decoding is performed via `String.decodeFromAsn1ContentBytes(rawValue)`, which internally uses
     * the standard library's [ByteArray.decodeToString].
     */
    val value: String by lazy { String.decodeFromAsn1ContentBytes(rawValue) }

    /**
     * Returns whether this string is valid:
     * - `true`: validation succeeded
     * - `false`: validation failed
     * - `null`: no validation implemented
     */
    abstract val isValid: Boolean?


    /**
     * UTF8 STRING (verbatim String)
     */
    @Serializable(with = Asn1Utf8StringSerializer::class)
    class UTF8 private constructor(
        rawValue: ByteArray,
        performValidation: Boolean
    ) : Asn1String(rawValue, performValidation) {
        override val tag = BERTags.UTF8_STRING.toULong()

        override val isValid: Boolean by lazy {
            !value.contains('\uFFFD')
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
     * UNIVERSAL STRING (no checks)
     * Validation is not implemented. This string format is deprecated for HTTPS certificates and its use in generally discouraged in favor of UTF-8 strings (see [Asn1String.UTF8]).
     */
    @Serializable(with = Asn1StringSerializer::class)
    class Universal private constructor(
        rawValue: ByteArray,
        performValidation: Boolean
    ) : Asn1String(rawValue, performValidation) {
        override val tag = BERTags.UNIVERSAL_STRING.toULong()

        /**
         * Always `null`, since no validation logic is implemented
         */
        override val isValid: Boolean? = null

        constructor(value: String) : this(value.encodeToByteArray(), false)

        @PublishedApi
        internal constructor(rawValue: ByteArray) : this(rawValue, false)
    }

    /**
     * VISIBLE STRING (checked)
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
     * IA5 STRING (checked)
     */
    @Serializable(with = Asn1Ia5StringSerializer::class)
    class IA5 private constructor(
        rawValue: ByteArray,
        performValidation: Boolean
    ) : Asn1String(rawValue, performValidation) {
        override val tag = BERTags.IA5_STRING.toULong()

        override val isValid: Boolean by lazy {
            Regex("[\\x00-\\x7E]*").matches(value)
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
     * TELETEX STRING (checked).
     *  This string format is deprecated for HTTPS certificates and its use in generally discouraged in favor of UTF-8 strings (see [Asn1String.UTF8]).
     */
    @Serializable(with = Asn1StringSerializer::class)
    class Teletex private constructor(
        rawValue: ByteArray,
        performValidation: Boolean
    ) : Asn1String(rawValue, performValidation) {
        override val tag = BERTags.T61_STRING.toULong()

        override val isValid: Boolean by lazy {
            Regex("[\\u0000-\\u00FF]*").matches(value)
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
     * BMP STRING (unchecked).
     * Validation is not implemented. This string format is deprecated for HTTPS certificates and its use in generally discouraged in favor of UTF-8 strings (see [Asn1String.UTF8]).
     */
    @Serializable(with = Asn1StringSerializer::class)
    class BMP private constructor(
        rawValue: ByteArray,
        performValidation: Boolean
    ) : Asn1String(rawValue, performValidation) {
        override val tag = BERTags.BMP_STRING.toULong()

        /**
         * Always `null`, since no validation logic is implemented
         */
        override val isValid: Boolean? = null

        constructor(value: String) : this(value.encodeToByteArray(), false)

        @PublishedApi
        internal constructor(rawValue: ByteArray) : this(rawValue, false)
    }

    /**
     * GENERAL STRING (checked)
     */
    @Serializable(with = Asn1StringSerializer::class)
    class General private constructor(
        rawValue: ByteArray,
        performValidation: Boolean
    ) : Asn1String(rawValue, performValidation) {
        override val tag = BERTags.GENERAL_STRING.toULong()

        override val isValid: Boolean by lazy {
            Regex("[\\x00-\\x7E]*").matches(value)
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
     * GRAPHIC STRING (checked)
     */
    @Serializable(with = Asn1StringSerializer::class)
    class Graphic private constructor(
        rawValue: ByteArray,
        performValidation: Boolean
    ) : Asn1String(rawValue, performValidation) {
        override val tag = BERTags.GRAPHIC_STRING.toULong()

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
     * PRINTABLE STRING (checked)
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
     * NUMERIC STRING (checked)
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

    companion object : Asn1Serializable<Asn1Primitive, Asn1String> {
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
            if (encoder is Asn1DerEncoder) {
                encoder.encodeSerializableValue(ByteArraySerializer(), value.encodeToDer())
            } else {
                encoder.encodeString(value.value)
            }
        }

        override fun deserialize(decoder: Decoder): Asn1String =
            if (decoder is Asn1DerDecoder) {
                ByteArraySerializer().deserialize(decoder).let { decodeFromDer(it) }
            } else {
                Asn1String.UTF8(decoder.decodeString())
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
    if (assertTag != null && src.tag != assertTag && assertTag != semanticTag) {
        throw Asn1TagMismatchException(assertTag, src.tag)
    }
    return if (src.tag == semanticTag) {
        decodeWithSemanticTag(src)
    } else {
        decodeImplicitContent(src.content)
    }
}

object Asn1Utf8StringSerializer : Asn1Serializable<Asn1Primitive, Asn1String.UTF8> {
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
        if (encoder is Asn1DerEncoder) {
            encoder.encodeSerializableValue(ByteArraySerializer(), value.encodeToDer())
        } else {
            encoder.encodeString(value.value)
        }
    }

    override fun deserialize(decoder: Decoder): Asn1String.UTF8 =
        if (decoder is Asn1DerDecoder) ByteArraySerializer().deserialize(decoder).let { decodeFromDer(it) }
        else Asn1String.UTF8(decoder.decodeString())
}

object Asn1VisibleStringSerializer : Asn1Serializable<Asn1Primitive, Asn1String.Visible> {
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
        if (encoder is Asn1DerEncoder) {
            encoder.encodeSerializableValue(ByteArraySerializer(), value.encodeToDer())
        } else {
            encoder.encodeString(value.value)
        }
    }

    override fun deserialize(decoder: Decoder): Asn1String.Visible =
        if (decoder is Asn1DerDecoder) ByteArraySerializer().deserialize(decoder).let { decodeFromDer(it) }
        else Asn1String.Visible(decoder.decodeString())
}

object Asn1Ia5StringSerializer : Asn1Serializable<Asn1Primitive, Asn1String.IA5> {
    override val leadingTags: Set<Asn1Element.Tag> = setOf(Asn1Element.Tag.STRING_IA5)
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor(ASN1_DESCRIPTOR_STRING, PrimitiveKind.STRING)

    override fun decodeFromTlv(src: Asn1Primitive, assertTag: Asn1Element.Tag?): Asn1String.IA5 =
        decodeImplicitlyTaggedAsn1StringSubtype(
            src,
            assertTag,
            Asn1Element.Tag.STRING_IA5,
            decodeWithSemanticTag = { it.decodeToIa5String() },
            decodeImplicitContent = { Asn1String.IA5(String.decodeFromAsn1ContentBytes(it)) },
        )

    override fun doDecode(src: Asn1Primitive): Asn1String.IA5 = src.decodeToIa5String()

    override fun serialize(encoder: Encoder, value: Asn1String.IA5) {
        if (encoder is Asn1DerEncoder) {
            encoder.encodeSerializableValue(ByteArraySerializer(), value.encodeToDer())
        } else {
            encoder.encodeString(value.value)
        }
    }

    override fun deserialize(decoder: Decoder): Asn1String.IA5 =
        if (decoder is Asn1DerDecoder) ByteArraySerializer().deserialize(decoder).let { decodeFromDer(it) }
        else Asn1String.IA5(decoder.decodeString())
}

object Asn1PrintableStringSerializer : Asn1Serializable<Asn1Primitive, Asn1String.Printable> {
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
        if (encoder is Asn1DerEncoder) {
            encoder.encodeSerializableValue(ByteArraySerializer(), value.encodeToDer())
        } else {
            encoder.encodeString(value.value)
        }
    }

    override fun deserialize(decoder: Decoder): Asn1String.Printable =
        if (decoder is Asn1DerDecoder) ByteArraySerializer().deserialize(decoder).let { decodeFromDer(it) }
        else Asn1String.Printable(decoder.decodeString())
}

object Asn1NumericStringSerializer : Asn1Serializable<Asn1Primitive, Asn1String.Numeric> {
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
        if (encoder is Asn1DerEncoder) {
            encoder.encodeSerializableValue(ByteArraySerializer(), value.encodeToDer())
        } else {
            encoder.encodeString(value.value)
        }
    }

    override fun deserialize(decoder: Decoder): Asn1String.Numeric =
        if (decoder is Asn1DerDecoder) ByteArraySerializer().deserialize(decoder).let { decodeFromDer(it) }
        else Asn1String.Numeric(decoder.decodeString())
}
