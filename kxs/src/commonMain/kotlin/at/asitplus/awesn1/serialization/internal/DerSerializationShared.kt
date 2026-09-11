// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(at.asitplus.awesn1.InternalAwesn1Api::class)

package at.asitplus.awesn1.serialization.internal

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.Asn1TagMismatchException
import at.asitplus.awesn1.TagClass
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.awesn1.serialization.Asn1OpenPolymorphicWithDefaultSerializer
import at.asitplus.awesn1.serialization.asn1Tag
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.SerializationException
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.descriptors.PolymorphicKind
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.StructureKind
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.internal.AbstractPolymorphicSerializer
import kotlinx.serialization.modules.SerializersModule

private val byteArrayDescriptor = ByteArraySerializer().descriptor
private val byteArraySerialName = byteArrayDescriptor.serialName.removeSuffix("?")

internal fun SerialDescriptor.isByteArrayLikeDescriptor(): Boolean {
    val descriptor = unwrapInlineDescriptorForAsn1()
    val normalizedName = descriptor.serialName.removeSuffix("?")
    return descriptor == byteArrayDescriptor ||
            normalizedName == byteArraySerialName ||
            (descriptor.kind is StructureKind.LIST &&
                    descriptor.elementsCount == 1 &&
                    descriptor.getElementDescriptor(0).kind == PrimitiveKind.BYTE)
}

internal tailrec fun SerialDescriptor.unwrapInlineDescriptorForAsn1(): SerialDescriptor =
    if (isInline && elementsCount == 1) getElementDescriptor(0).unwrapInlineDescriptorForAsn1() else this

internal fun SerialDescriptor.isKotlinUByteDescriptor(): Boolean =
    serialName.removeSuffix("?") == "kotlin.UByte"

internal fun SerialDescriptor.isKotlinUShortDescriptor(): Boolean =
    serialName.removeSuffix("?") == "kotlin.UShort"

internal fun SerialDescriptor.isKotlinUIntDescriptor(): Boolean =
    serialName.removeSuffix("?") == "kotlin.UInt"

internal fun SerialDescriptor.isKotlinULongDescriptor(): Boolean =
    serialName.removeSuffix("?") == "kotlin.ULong"

internal fun SerialDescriptor.isKotlinUnsignedIntegerDescriptor(): Boolean =
    isKotlinUByteDescriptor() || isKotlinUShortDescriptor() || isKotlinUIntDescriptor() || isKotlinULongDescriptor()

internal tailrec fun SerialDescriptor.inlineChainContains(serialName: String): Boolean =
    if (this.serialName.removeSuffix("?") == serialName) true
    else if (isInline && elementsCount == 1) getElementDescriptor(0).inlineChainContains(serialName)
    else false

internal fun SerialDescriptor.requireNoAsn1TagOnInlineBackingProperty() {
    if (isInline && elementsCount == 1 && asn1Tag(0) != null) {
        throw SerializationException(
            "@Asn1Tag on inline/value class backing property is not supported for $serialName. " +
                    "Annotate the inline/value class itself instead."
        )
    }
}

@Throws(SerializationException::class)
internal fun rejectAsn1TagOnChoice(
    choiceSerialName: String,
    inlineAsn1Tag: Asn1Tag? = null,
    propertyAsn1Tag: Asn1Tag? = null,
    classAsn1Tag: Asn1Tag? = null,
) {
    val tagSource = when {
        propertyAsn1Tag != null -> "property"
        inlineAsn1Tag != null -> "inline"
        classAsn1Tag != null -> "class"
        else -> return
    }
    val tagNumber = propertyAsn1Tag?.tagNumber ?: inlineAsn1Tag?.tagNumber ?: classAsn1Tag?.tagNumber
    throw SerializationException(
        "@Asn1Tag on ASN.1 CHOICE is not supported for $choiceSerialName ($tagSource tag $tagNumber). " +
                "Model the tagged wrapper explicitly."
    )
}

@OptIn(InternalSerializationApi::class)
internal fun <T> resolveOpenPolymorphicAsn1SerializerOrNull(
    serializer: SerializationStrategy<T>,
    serializersModule: SerializersModule,
): SerializationStrategy<*>? {
    if (serializer.descriptor.kind !is PolymorphicKind.OPEN) return null
    return when (serializer) {
        is AbstractPolymorphicSerializer<*> ->
            serializersModule.getContextual(serializer.baseClass, emptyList())
        is Asn1OpenPolymorphicWithDefaultSerializer<*> ->
            serializersModule.getContextual(serializer.baseClass, emptyList()) ?: serializer.defaultSerializer
        else -> null
    }
}

@OptIn(InternalSerializationApi::class)
internal fun <T> resolveOpenPolymorphicAsn1SerializerOrNull(
    deserializer: DeserializationStrategy<T>,
    serializersModule: SerializersModule,
): DeserializationStrategy<*>? {
    if (deserializer.descriptor.kind !is PolymorphicKind.OPEN) return null
    return when (deserializer) {
        is AbstractPolymorphicSerializer<*> ->
            serializersModule.getContextual(deserializer.baseClass, emptyList())
        is Asn1OpenPolymorphicWithDefaultSerializer<*> ->
            serializersModule.getContextual(deserializer.baseClass, emptyList()) ?: deserializer.defaultSerializer
        else -> null
    }
}

/**
 * Ensures encoder is [DerEncoder] and returns it.
 *
 * @throws SerializationException if called with a non-DER encoder
 */
@Throws(SerializationException::class)
internal fun Encoder.requireDerEncoder(serializerName: String): DerEncoder {
    if (this !is DerEncoder) {
        throw SerializationException(
            "$serializerName supports ASN.1 DER format only. " +
                    "Use DER.encodeToDer(...) / DER.encodeToTlv(...) instead of non-ASN.1 formats."
        )
    }
    return this
}

/**
 * Ensures decoder is [DerDecoder] and returns it.
 *
 * @throws SerializationException if called with a non-DER decoder
 */
@Throws(SerializationException::class)
internal fun Decoder.requireDerDecoder(serializerName: String): DerDecoder {
    if (this !is DerDecoder) {
        throw SerializationException(
            "$serializerName supports ASN.1 DER format only. " +
                    "Use DER.decodeFromDer(...) / DER.decodeFromTlv(...) instead of non-ASN.1 formats."
        )
    }
    return this
}

/** Applies the value-path implicit tag rule and validates [actual] against it. */
@Throws(SerializationException::class)
internal fun Asn1Element.Tag.Template.resolveAgainst(actual: Asn1Element.Tag): Asn1Element.Tag {
    val expectedTag = Asn1Element.Tag(
        tagValue = tagValue,
        tagClass = tagClass ?: TagClass.CONTEXT_SPECIFIC,
        constructed = constructed ?: actual.isConstructed,
    )
    if (actual != expectedTag) {
        throw SerializationException(Asn1TagMismatchException(expectedTag, actual))
    }
    return expectedTag
}

internal fun Asn1Element.isAsn1NullElement(): Boolean =
    this is Asn1Primitive &&
            tag == Asn1Element.Tag.NULL &&
            contentLength == 0
