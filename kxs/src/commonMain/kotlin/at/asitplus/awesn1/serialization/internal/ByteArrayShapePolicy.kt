// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.serialization.internal

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.Asn1OctetString
import at.asitplus.awesn1.encoding.asAsn1BitString
import at.asitplus.awesn1.serialization.isAsn1BitString
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.StructureKind

internal enum class ByteArrayShape {
    OCTET_STRING,
    BIT_STRING,
    NOT_APPLICABLE,
}

internal object ByteArrayShapePolicy {
    private val byteArrayDescriptor = ByteArraySerializer().descriptor

    fun shapeForByteArray(bitStringRequested: Boolean): ByteArrayShape =
        if (bitStringRequested) ByteArrayShape.BIT_STRING else ByteArrayShape.OCTET_STRING

    fun shapeForDescriptor(
        descriptor: SerialDescriptor,
        bitStringRequested: Boolean,
    ): ByteArrayShape =
        if (descriptor == byteArrayDescriptor) {
            if (bitStringRequested) ByteArrayShape.BIT_STRING else ByteArrayShape.OCTET_STRING
        } else {
            ByteArrayShape.NOT_APPLICABLE
        }

    /**
     * Resolves byte-array shape from serializer [descriptor] and bit-string hints.
     *
     * @throws SerializationException if `@Asn1BitString` is requested for a serializer that is not byte-array compatible
     */
    @Throws(SerializationException::class)
    fun resolveSerializerShape(
        descriptor: SerialDescriptor,
        layoutPlan: DerLayoutPlanContext,
        inlineAsBitString: Boolean = false,
        propertyAsBitString: Boolean = false,
        includeDescriptorAsBitString: Boolean = false,
    ): ByteArrayShape {
        val bitStringRequested = inlineAsBitString || propertyAsBitString ||
                (includeDescriptorAsBitString && descriptor.isAsn1BitString)
        if (bitStringRequested && !layoutPlan.isBitStringCompatible(descriptor)) {
            throw SerializationException(
                "@Asn1BitString can only be used with ByteArray-compatible serializers, but got ${descriptor.serialName}"
            )
        }
        return shapeForDescriptor(
            descriptor = descriptor,
            bitStringRequested = bitStringRequested,
        )
    }

    /**
     * Encodes [bytes] according to [shape].
     *
     * @throws SerializationException when [shape] is [ByteArrayShape.NOT_APPLICABLE]
     */
    @Throws(SerializationException::class)
    fun encodeByteArray(
        bytes: ByteArray,
        shape: ByteArrayShape,
    ): Asn1Element = when (shape) {
        ByteArrayShape.BIT_STRING -> Asn1BitString(bytes).encodeToTlv()
        ByteArrayShape.OCTET_STRING -> Asn1OctetString(bytes)
        ByteArrayShape.NOT_APPLICABLE -> throw SerializationException("Byte-array shape is not applicable")
    }

    /**
     * Decodes [primitive] into bytes according to [shape].
     *
     * @throws SerializationException when BIT STRING decoding fails for invalid ASN.1 payload/tag
     * @throws SerializationException when [shape] is [ByteArrayShape.NOT_APPLICABLE]
     */
    @Throws(SerializationException::class)
    fun decodeByteArray(
        primitive: Asn1Primitive,
        shape: ByteArrayShape,
        tagToValidate: Asn1Element.Tag?,
    ): ByteArray = when (shape) {
        ByteArrayShape.BIT_STRING ->
            primitive.asAsn1BitString(tagToValidate ?: Asn1Element.Tag.BIT_STRING).apply {
                if (numPaddingBits != 0.toByte()) throw SerializationException(
                    "Byte Arrays deserialized from BIT STRING must not have padding bits. Found $numPaddingBits padding bits. " +
                            "If you require padding, directly use Asn1BitString to represent the property."
                )
            }.bitCarryingBytes

        ByteArrayShape.OCTET_STRING -> primitive.content
        ByteArrayShape.NOT_APPLICABLE -> throw SerializationException("Byte-array shape is not applicable")
    }

    fun defaultTagForDescriptor(
        descriptor: SerialDescriptor,
        byteArrayShape: ByteArrayShape,
    ): Asn1Element.Tag? =
        if (descriptor.isSetDescriptor) Asn1Element.Tag.SET
        else when (byteArrayShape) {
            ByteArrayShape.BIT_STRING -> Asn1Element.Tag.BIT_STRING
            ByteArrayShape.OCTET_STRING -> Asn1Element.Tag.OCTET_STRING
            ByteArrayShape.NOT_APPLICABLE -> when (descriptor.kind) {
                is StructureKind.CLASS, is StructureKind.OBJECT -> Asn1Element.Tag.SEQUENCE
                is StructureKind.LIST -> Asn1Element.Tag.SEQUENCE
                is StructureKind.MAP -> Asn1Element.Tag.SEQUENCE
                else -> null // primitive tags validated in decodeValue()
            }
        }
}
