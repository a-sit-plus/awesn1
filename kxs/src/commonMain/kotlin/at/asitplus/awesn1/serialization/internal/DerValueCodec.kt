// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(at.asitplus.awesn1.InternalAwesn1Api::class)

package at.asitplus.awesn1.serialization.internal

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.*
import at.asitplus.awesn1.serialization.Asn1Serializable
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.PolymorphicKind
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.SerialKind
import kotlinx.serialization.encoding.AbstractDecoder
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.modules.SerializersModule
import kotlin.time.Instant

/** Stateless conversion between Kotlin scalar values and individual ASN.1 elements. */
internal object DerValueCodec {

    /** Returns `null` when [value] is not one of the scalar values handled directly by DER. */
    fun encodePrimitiveOrNull(value: Any, byteArrayShape: ByteArrayShape): Asn1Element? = when (value) {
        is ByteArray -> ByteArrayShapePolicy.encodeByteArray(value, byteArrayShape)
        is Boolean -> value.encodeToAsn1Primitive()
        is Byte -> value.toInt().encodeToAsn1Primitive()
        is UByte -> value.toUInt().encodeToAsn1Primitive()
        is Short -> value.toInt().encodeToAsn1Primitive()
        is UShort -> value.toUInt().encodeToAsn1Primitive()
        is Int -> value.encodeToAsn1Primitive()
        is UInt -> value.encodeToAsn1Primitive()
        is Float -> value.encodeToAsn1Primitive()
        is Long -> value.encodeToAsn1Primitive()
        is ULong -> value.encodeToAsn1Primitive()
        is Double -> value.encodeToAsn1Primitive()
        is String -> value.encodeToAsn1Primitive()
        is Char -> value.toString().encodeToAsn1Primitive()
        else -> null
    }

    fun decodePrimitive(
        element: Asn1Element,
        effectiveDescriptor: SerialDescriptor,
        declaredDescriptor: SerialDescriptor,
        expectedTag: Asn1Element.Tag?,
    ): Any = when (effectiveDescriptor.kind) {
        PolymorphicKind.OPEN -> throw SerializationException(
            "Open polymorphic decoding is not supported via primitive decode path for ${effectiveDescriptor.serialName}. " +
                    "Register an ASN.1 open-polymorphic serializer in DER { serializersModule = ... } " +
                    "via polymorphicByTag(...) or polymorphicByOid(...)."
        )

        PolymorphicKind.SEALED -> throw SerializationException(
            "Sealed polymorphic decoding is not supported via primitive decode path for ${effectiveDescriptor.serialName}. " +
                    "ASN.1 CHOICE is supported for sealed types in composite decoding paths."
        )

        PrimitiveKind.BOOLEAN -> element.asPrimitive().decodeToBoolean(expectedTag ?: Asn1Element.Tag.BOOL)
        PrimitiveKind.BYTE -> element.asPrimitive().decodeToInt(expectedTag ?: Asn1Element.Tag.INT).let {
            if (declaredDescriptor.inlineChainContains("kotlin.UByte")) it.toStrictUByteBacking()
            else it.toStrictByte()
        }

        PrimitiveKind.CHAR -> element.asPrimitive().decodeString(expectedTag)
            .also { if (it.length != 1) throw SerializationException("String is not a char") }[0]

        PrimitiveKind.DOUBLE -> element.asPrimitive().decodeToDouble(expectedTag ?: Asn1Element.Tag.REAL)
        PrimitiveKind.FLOAT -> element.asPrimitive().decodeToFloat(expectedTag ?: Asn1Element.Tag.REAL)
        PrimitiveKind.INT -> if (declaredDescriptor.inlineChainContains("kotlin.UInt")) {
            element.asPrimitive().decodeToUInt(expectedTag ?: Asn1Element.Tag.INT).toInt()
        } else {
            element.asPrimitive().decodeToInt(expectedTag ?: Asn1Element.Tag.INT)
        }

        PrimitiveKind.LONG -> if (declaredDescriptor.inlineChainContains("kotlin.ULong")) {
            element.asPrimitive().decodeToULong(expectedTag ?: Asn1Element.Tag.INT).toLong()
        } else {
            element.asPrimitive().decodeToLong(expectedTag ?: Asn1Element.Tag.INT)
        }

        PrimitiveKind.SHORT -> element.asPrimitive().decodeToInt(expectedTag ?: Asn1Element.Tag.INT).let {
            if (declaredDescriptor.inlineChainContains("kotlin.UShort")) it.toStrictUShortBacking()
            else it.toStrictShort()
        }

        PrimitiveKind.STRING -> element.asPrimitive().decodeString(expectedTag)
        SerialKind.ENUM -> element.asPrimitive().decodeToEnumOrdinal(expectedTag ?: Asn1Element.Tag.ENUM)
        else -> throw SerializationException(
            "Unsupported descriptor kind ${declaredDescriptor.kind} for ${effectiveDescriptor.serialName} in decodeValue(). " +
                    "Provide a custom serializer or use a supported ASN.1 mapping shape."
        )
    }

    fun decodeEnumOrdinal(element: Asn1Primitive, expectedTag: Asn1Element.Tag?): Int =
        element.decodeToEnumOrdinal(expectedTag ?: Asn1Element.Tag.ENUM).let {
            if (it < 0) throw SerializationException("Negative ordinal $it cannot be auto-mapped to an enum value")
            if (it > Int.MAX_VALUE.toLong()) throw SerializationException("Ordinal $it too large!")
            it.toInt()
        }

    fun <T> decodeEnum(
        deserializer: DeserializationStrategy<T>,
        element: Asn1Primitive,
        expectedTag: Asn1Element.Tag?,
        serializersModule: SerializersModule,
    ): T {
        val ordinal = decodeEnumOrdinal(element, expectedTag)
        return deserializer.deserialize(object : AbstractDecoder() {
            override val serializersModule: SerializersModule = serializersModule
            override fun decodeEnum(enumDescriptor: SerialDescriptor): Int = ordinal
            override fun decodeElementIndex(descriptor: SerialDescriptor): Int = CompositeDecoder.DECODE_DONE
        })
    }

    fun encodeInstant(value: Instant): Asn1Element = Asn1Time(value).encodeToTlv()

    fun decodeInstant(element: Asn1Primitive, expectedTag: Asn1Element.Tag?): Instant {
        if (expectedTag == null) return element.decodeToInstant()

        if (expectedTag == Asn1Element.Tag.TIME_UTC) {
            return catchingUnwrapped { Instant.decodeUtcTimeFromAsn1ContentBytes(element.content) }.getOrElse {
                throw SerializationException(it)
            }
        }

        if (expectedTag == Asn1Element.Tag.TIME_GENERALIZED) {
            return catchingUnwrapped { Instant.decodeGeneralizedTimeFromAsn1ContentBytes(element.content) }.getOrElse {
                throw SerializationException(it)
            }
        }

        catchingUnwrapped { Instant.decodeUtcTimeFromAsn1ContentBytes(element.content) }.getOrNull()?.let { return it }
        catchingUnwrapped { Instant.decodeGeneralizedTimeFromAsn1ContentBytes(element.content) }.getOrNull()
            ?.let { return it }

        throw SerializationException(
            "Failed to decode implicitly tagged ASN.1 TIME for kotlin.time.Instant: " +
                    "content is neither UTCTime nor GeneralizedTime"
        )
    }

    @Suppress("UNCHECKED_CAST")
    fun decodeAsn1Serializable(
        serializer: Asn1Serializable<*, *>,
        element: Asn1Element,
        expectedTag: Asn1Element.Tag?,
    ): Any = runWrappingAs(a = ::SerializationException) {
        when (element) {
            is Asn1Primitive -> {
                val primitiveDecoder = serializer as? Asn1Decodable<Asn1Primitive, *>
                    ?: throw SerializationException(
                        "Serializer ${serializer.descriptor.serialName} cannot decode ASN.1 primitive values"
                    )
                primitiveDecoder.decodeFromTlv(element, expectedTag)
            }

            is Asn1Structure -> {
                val structureDecoder = serializer as? Asn1Decodable<Asn1Structure, *>
                    ?: throw SerializationException(
                        "Serializer ${serializer.descriptor.serialName} cannot decode ASN.1 structure values"
                    )
                structureDecoder.decodeFromTlv(element, expectedTag)
            }
        }
    }

    @OptIn(ExperimentalSerializationApi::class)
    fun decodeRawElement(
        deserializer: DeserializationStrategy<*>,
        element: Asn1Element,
        expectedTag: Asn1Element.Tag?,
    ): Any {
        if (deserializer == Asn1OctetStringFallbackBase64Serializer) {
            if (expectedTag == null && element.tag != Asn1Element.Tag.OCTET_STRING) {
                throw SerializationException(
                    Asn1TagMismatchException(Asn1Element.Tag.OCTET_STRING, element.tag)
                )
            }
            return Asn1OctetString(element.asPrimitive().content)
        }

        require(deserializer is Asn1ElementFallbackBase64SerializerBase<*>) {
            "Reserved SerialName for Asn1ElementFallbackBase64SerializerBase reused by: ${deserializer::class.simpleName}"
        }
        return deserializer.decodeFromAsn1Element(element)
    }
}

private fun Asn1Primitive.decodeString(implicitTagOverride: Asn1Element.Tag?): String {
    // Kotlin String cannot carry the ASN.1 string type, so accepting a foreign one would mean re-encoding it as
    // UTF8String and silently rewriting the wire. Use Asn1String to keep the tag, or @Asn1Tag to override it.
    val expected = implicitTagOverride ?: Asn1Element.Tag.STRING_UTF8
    if (tag != expected) throw SerializationException(Asn1TagMismatchException(expected, tag))
    return if (implicitTagOverride == null) decodeToString() else String.decodeFromAsn1ContentBytes(content)
}

private fun Int.toStrictByte(): Byte =
    if (this in Byte.MIN_VALUE..Byte.MAX_VALUE) toByte()
    else throw SerializationException("ASN.1 INTEGER value $this is out of range for Byte")

private fun Int.toStrictShort(): Short =
    if (this in Short.MIN_VALUE..Short.MAX_VALUE) toShort()
    else throw SerializationException("ASN.1 INTEGER value $this is out of range for Short")

private fun Int.toStrictUByteBacking(): Byte =
    if (this in 0..UByte.MAX_VALUE.toInt()) toByte()
    else throw SerializationException("ASN.1 INTEGER value $this is out of range for UByte")

private fun Int.toStrictUShortBacking(): Short =
    if (this in 0..UShort.MAX_VALUE.toInt()) toShort()
    else throw SerializationException("ASN.1 INTEGER value $this is out of range for UShort")
