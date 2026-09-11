// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(at.asitplus.awesn1.InternalAwesn1Api::class)

package at.asitplus.awesn1.serialization.internal

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.serialization.Asn1Serializable
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.awesn1.serialization.Der
import at.asitplus.awesn1.serialization.asn1Tag
import at.asitplus.awesn1.serialization.isAsn1OctetStringEncapsulatedDescriptor
import kotlinx.serialization.*
import kotlinx.serialization.descriptors.PolymorphicKind
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.StructureKind
import kotlinx.serialization.encoding.AbstractEncoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.internal.AbstractPolymorphicSerializer
import kotlinx.serialization.modules.SerializersModule
import kotlin.time.Instant


/**
 * Holder for ASN.1 elements during serialization process.
 * Can hold either a concrete element or a placeholder that needs to be resolved later.
 */
private sealed class Asn1ElementHolder {
    data class Element(val element: Asn1Element) : Asn1ElementHolder()
    class StructurePlaceholder(
        val childSerializer: DerEncoder,
        val descriptor: SerialDescriptor,
        val tagTemplate: Asn1Element.Tag.Template?,
    ) : Asn1ElementHolder()
}

private data class PendingStructure(val tagTemplate: Asn1Element.Tag.Template?)


@ExperimentalSerializationApi
class DerEncoder internal constructor(
    override val der: Der,
    private val analysis: DerAnalysisContext = DerAnalysisContext(der.configuration.explicitNulls),
    // Shared across the whole encode so structural recursion is bounded (mirror of DerDecoder). Serializing a deeply
    // nested recursive @Serializable type recurses per level (serialize -> encodeSerializableElement -> serialize ->
    // ...), which the iterative core encoder cannot flatten; this turns a would-be StackOverflowError into a clean
    // SerializationException. Every child encoder MUST receive this same instance.
    private val depthGuard: DerDepthGuard = DerDepthGuard(),
    private val honorRuntimeAsn1Encodable: Boolean = true,
) : AbstractEncoder(), at.asitplus.awesn1.serialization.DerEncoder {

    override val serializersModule: SerializersModule
        get() = der.configuration.serializersModule

    private val buffer = mutableListOf<Asn1ElementHolder>()
    private var pendingPropertyContext: DerPropertyContext? = null

    private val inlineHintState = DerInlineHintState()
    private var pendingStructure: PendingStructure? = null
    private var pendingDiscriminatorOid: ObjectIdentifier? = null

    @Suppress("UNCHECKED_CAST")
    internal fun <T : Any> encodeSelectedValue(selection: DerEncodeSelection<T>, value: T) {
        val previousDiscriminatorOid = pendingDiscriminatorOid
        pendingDiscriminatorOid = selection.discriminatorOid
        try {
            encodeSerializableValue(selection.serializer as SerializationStrategy<T>, value)
        } finally {
            pendingDiscriminatorOid = previousDiscriminatorOid
        }
    }


    @OptIn(ExperimentalSerializationApi::class)
    override fun encodeInline(descriptor: SerialDescriptor): Encoder {
        inlineHintState.captureInlineHintsFrom(descriptor)
        return this
    }

    override fun encodeBoolean(value: Boolean) {
        encodeValue(value)
    }

    override fun encodeByte(value: Byte) {
        encodeValue(value)
    }

    override fun encodeShort(value: Short) {
        encodeValue(value)
    }

    override fun encodeInt(value: Int) {
        encodeValue(value)
    }

    override fun encodeLong(value: Long) {
        encodeValue(value)
    }

    override fun encodeDouble(value: Double) {
        encodeValue(value)
    }

    override fun encodeFloat(value: Float) {
        encodeValue(value)
    }

    override fun encodeChar(value: Char) {
        encodeValue(value)
    }

    override fun encodeString(value: String) {
        encodeValue(value)
    }

    /**
     * Encodes primitive/runtime values into ASN.1 elements.
     *
     * @throws SerializationException if tag/annotation constraints are invalid for the current value
     */
    override fun encodeValue(value: Any) {
        val inlineHints = inlineHintState.consume()
        val propertyContext = consumePropertyContextOrNull()
        val tagTemplate = tagSite(inlineHints, propertyContext, typeDescriptor = null)

        if (value is Asn1Element && tagTemplate != null) {
            throw SerializationException(
                "Raw Asn1Element must not use @Asn1Tag; remove the override or use a strongly typed value/wrapper"
            )
        }

        val element = when (value) {
            is Asn1Element -> value
            is Asn1Encodable<*> -> value.encodeToTlv()
            else -> DerValueCodec.encodePrimitiveOrNull(
                value = value,
                byteArrayShape = ByteArrayShapePolicy.shapeForByteArray(
                    inlineHints.asBitString || propertyContext?.propertyAsBitString == true,
                ),
            )
        }

        if (element == null) {
            super.encodeValue(value)
            return
        }

        appendElement(element, tagTemplate)
    }

    /**
     * Encodes null according to nullable layout analysis and explicit-null configuration.
     *
     * @throws SerializationException if nullable null encoding is ambiguous at current property location
     */
    override fun encodeNull() {
        val inlineHints = inlineHintState.consume()
        val propertyContext = consumePropertyContextOrNull() ?: return
        val propertyDescriptor = propertyContext.propertyDescriptor
        requireRepresentableCollectionNull(propertyContext)
        val nullEncodingAnalysis = analysis.analyzeNullable(
            descriptor = propertyDescriptor,
            propertyAsn1Tag = propertyContext.propertyAsn1Tag,
            inlineAsn1Tag = inlineHints.tag,
            propertyAsBitString = propertyContext.propertyAsBitString,
            inlineAsBitString = inlineHints.asBitString,
        )
        if (nullEncodingAnalysis.isAmbiguous) {
            throw SerializationException(
                ambiguousAsn1NullEncodingMessage(
                    ownerSerialName = propertyContext.ownerSerialName,
                    propertyName = propertyContext.propertyName ?: propertyDescriptor.serialName,
                    propertyIndex = propertyContext.index,
                )
            )
        }
        if (!nullEncodingAnalysis.encodeNullEnabled) return

        val tagTemplate = tagSite(inlineHints, propertyContext, typeDescriptor = propertyDescriptor)
        appendNullElement(propertyDescriptor, tagTemplate)
    }

    override fun encodeElement(descriptor: SerialDescriptor, index: Int): Boolean {
        pendingPropertyContext = (descriptor to index).toDerPropertyContext()
        return super.encodeElement(descriptor, index)
    }

    override fun shouldEncodeElementDefault(descriptor: SerialDescriptor, index: Int): Boolean =
        der.configuration.encodeDefaults

    override fun encodeEnum(enumDescriptor: SerialDescriptor, index: Int) {
        val propertyContext = consumePropertyContextOrNull()
        val inlineHints = inlineHintState.consume()
        val tagTemplate = tagSite(
            inlineHints.copy(tag = inlineHints.tag ?: propertyContext?.propertyDescriptor?.asn1Tag),
            propertyContext,
            typeDescriptor = enumDescriptor,
        )
        appendElement(Asn1.Enumerated(index), tagTemplate)
    }

    @OptIn(InternalSerializationApi::class)
    /**
     * Main serialization pipeline for DER encoding.
     *
     * @throws SerializationException if serializer/value/tag/nullability/polymorphism constraints are violated
     */
    @Throws(SerializationException::class)
    override fun <T> encodeSerializableValue(serializer: SerializationStrategy<T>, value: T) {
        try {
            encodeSerializableValueImpl(serializer, value)
        } finally {
            pendingPropertyContext = null
        }
    }

    @OptIn(InternalSerializationApi::class)
    private fun <T> encodeSerializableValueImpl(serializer: SerializationStrategy<T>, value: T) {
        if (value != null && serializer.descriptor.isKotlinUnsignedIntegerDescriptor()) {
            encodeValue(value)
            return
        }
        if (value != null && serializer.descriptor.isInline) {
            super<AbstractEncoder>.encodeSerializableValue(serializer, value)
            return
        }

        val inlineHints = inlineHintState.consume()
        val propertyContext = pendingPropertyContext
        val propertyDescriptor = propertyContext?.propertyDescriptor
        val valueSite = analysis.prepareValue(
            descriptor = serializer.descriptor,
            nullAnalysisDescriptor = when {
                serializer.descriptor.isNullable -> serializer.descriptor
                propertyDescriptor?.isNullable == true -> propertyDescriptor
                else -> serializer.descriptor
            },
            inlineHints = inlineHints,
            propertyContext = propertyContext,
            propertyAsBitString = propertyContext?.propertyAsBitString == true,
            includeDescriptorAsBitString = true,
        )
        valueSite.validateSerializerAnnotations(
            // Asn1OctetString has a concrete wire representation despite sharing the opaque element descriptor.
            allowTaggedRawElementDescriptor = serializer == Asn1OctetStringFallbackBase64Serializer,
            isGenericAsn1StringSerializer = serializer == Asn1String.Companion,
        )
        valueSite.requireUnambiguousNull()

        if (value == null) {
            encodeSerializableNull(valueSite)
            return
        }

        encodeNonNullSerializableValue(serializer, value, valueSite)
    }

    private fun encodeSerializableNull(valueSite: DerValueSite) {
        if (!valueSite.nullEncoding.encodeNullEnabled) {
            valueSite.propertyContext?.let(::requireRepresentableCollectionNull)
            return
        }
        appendNullElement(valueSite.nullAnalysisDescriptor, valueSite.tagTemplate)
    }

    @OptIn(InternalSerializationApi::class)
    @Suppress("UNCHECKED_CAST")
    private fun <T> encodeNonNullSerializableValue(
        serializer: SerializationStrategy<T>,
        value: T,
        valueSite: DerValueSite,
    ) {
        if (value is Instant && serializer.descriptor.isKotlinTimeInstantDescriptor()) {
            appendElement(DerValueCodec.encodeInstant(value), valueSite.tagTemplate)
            return
        }

        if (serializer.descriptor.serialName.removeSuffix("?") == ASN1_DESCRIPTOR_ELEMENT_TREE) {
            val element = value as Asn1Element
            if (der.configuration.explicitNulls && valueSite.nullAnalysisDescriptor.isNullable &&
                element.isAsn1NullElement()
            ) {
                throw SerializationException(valueSite.ambiguousNullEncodingMessage())
            }
            appendElement(element, valueSite.tagTemplate)
            return
        }

        resolveOpenPolymorphicAsn1SerializerOrNull(serializer, serializersModule)?.let { openSerializer ->
            if (openSerializer.descriptor == serializer.descriptor) {
                throw SerializationException(
                    "Open polymorphism for ${serializer.descriptor.serialName} resolved to itself. " +
                            "Register an ASN.1 open-polymorphic serializer in DER { serializersModule = ... }."
                )
            }
            // Only a tag supplied by the enclosing property/inline wrapper crosses an open-polymorphic dispatch.
            // A tag on the open base descriptor belongs to that descriptor, not to every registered subtype.
            val inheritedTagTemplate = tagSite(
                valueSite.inlineHints,
                valueSite.propertyContext,
                typeDescriptor = null,
            )
            if (openSerializer !is Asn1TagDiscriminatedOpenPolymorphicSerializer<*> &&
                inheritedTagTemplate != null && pendingStructure == null) {
                pendingStructure = PendingStructure(inheritedTagTemplate)
            }
            try {
                return encodeSerializableValue(openSerializer as SerializationStrategy<T>, value)
            } finally {
                if (pendingStructure != null) {
                    pendingStructure = null
                }
            }
        }

        if (serializer.descriptor.kind is PolymorphicKind.OPEN && serializer is AbstractPolymorphicSerializer<*>) {
            throw SerializationException(
                "Open polymorphism for ${serializer.descriptor.serialName} requires an ASN.1 serializer " +
                        "registered in DER { serializersModule = ... } via polymorphicByTag(...) " +
                        "or polymorphicByOid(...)."
            )
        }

        if (serializer is SealedClassSerializer<*>) {
            encodeChoiceSerializableValue(
                serializer = serializer,
                value = value,
                inlineAnnotation = valueSite.inlineHints.tag,
                propertyAnnotation = valueSite.effectivePropertyTag,
            )
            return
        }

        when {
            valueSite.byteArrayShape != ByteArrayShape.NOT_APPLICABLE -> {
                val baseElement = ByteArrayShapePolicy.encodeByteArray(value as ByteArray, valueSite.byteArrayShape)
                appendElement(baseElement, valueSite.tagTemplate)
            }

            serializer is Asn1Serializable<*, *> && value is Asn1Encodable<*> ->
                appendElement(value.encodeToTlv(), valueSite.tagTemplate)

            value is Asn1Element -> appendElement(value, valueSite.tagTemplate)

            honorRuntimeAsn1Encodable && value is Asn1Encodable<*> ->
                appendElement(value.encodeToTlv(), valueSite.tagTemplate)

            else -> encodeWithKotlinxSerializer(serializer, value, valueSite.tagTemplate)
        }
    }

    private fun <T> encodeWithKotlinxSerializer(
        serializer: SerializationStrategy<T>,
        value: T,
        tagTemplate: Asn1Element.Tag.Template?,
    ) {
        val forwardsToBeginStructure = serializer.descriptor.kind.let {
            it is StructureKind.CLASS || it is StructureKind.OBJECT ||
                    it is StructureKind.LIST || it is StructureKind.MAP
        }

        if (forwardsToBeginStructure && pendingStructure == null) {
            pendingStructure = PendingStructure(tagTemplate)
        }

        try {
            super<AbstractEncoder>.encodeSerializableValue(serializer, value)
        } finally {
            if (forwardsToBeginStructure && pendingStructure != null) {
                pendingStructure = null
            }
        }
    }

    @OptIn(InternalSerializationApi::class)
    @Suppress("UNCHECKED_CAST")
    /**
     * Encodes sealed-polymorphic CHOICE values as exactly one ASN.1 element.
     *
     * @throws SerializationException if no concrete arm can be resolved or arm encoding is invalid
     */
    @Throws(SerializationException::class)
    private fun encodeChoiceSerializableValue(
        serializer: SealedClassSerializer<*>,
        value: Any?,
        inlineAnnotation: Asn1Tag?,
        propertyAnnotation: Asn1Tag?,
    ) {
        val sealedSerializer = serializer as SealedClassSerializer<Any>

        rejectAsn1TagOnChoice(
            choiceSerialName = serializer.descriptor.serialName,
            inlineAsn1Tag = inlineAnnotation,
            propertyAsn1Tag = propertyAnnotation,
            classAsn1Tag = serializer.descriptor.asn1Tag,
        )
        val selectedSerializer = sealedSerializer.findPolymorphicSerializerOrNull(this, value as Any)
            ?: throw SerializationException(
                "Could not resolve concrete serializer for CHOICE value of ${serializer.descriptor.serialName}: ${value::class}"
            )

        val childSerializer = DerEncoder(
            der = der,
            analysis = analysis,
            depthGuard = depthGuard,
            honorRuntimeAsn1Encodable = false,
        )
        childSerializer.encodeSerializableValue(selectedSerializer as SerializationStrategy<Any?>, value)
        val elements = childSerializer.encodeToTLV()
        if (elements.size != 1) {
            throw SerializationException(
                "ASN.1 CHOICE arm must encode to exactly one element, got ${elements.size} for ${selectedSerializer.descriptor.serialName}"
            )
        }

        appendElement(elements.first())
    }

    /**
     * Starts structure encoding by creating a child encoder placeholder.
     *
     * @throws SerializationException if optional layout is ambiguous for class/object descriptors
     */
    override fun beginStructure(descriptor: SerialDescriptor): DerEncoder {
        // Bound structural recursion before descending another level (see [DerDepthGuard]). Balanced by the
        // matching endStructure() decrement.
        depthGuard.enter(der.configuration.maxNestingDepth, descriptor.serialName)

        if (descriptor.kind is StructureKind.CLASS ||
            descriptor.kind is StructureKind.OBJECT
        ) {
            analysis.validateOptionalLayout(descriptor)?.let { }
        }
        val pending = pendingStructure
        val tagTemplate = if (pending != null) {
            inlineHintState.clear()
            pendingPropertyContext = null
            pendingStructure = null
            pending.tagTemplate
        } else {
            val propertyContext = consumePropertyContextOrNull()
            tagSite(inlineHintState.consume(), propertyContext, typeDescriptor = descriptor)
        }

        val childSerializer = DerEncoder(
            der = der,
            analysis = analysis,
            depthGuard = depthGuard,
        )

        pendingDiscriminatorOid?.let { elem ->
            // prepend as the *first* element in the child structure
            childSerializer.buffer.add(0, Asn1ElementHolder.Element(elem.encodeToTlv()))
            pendingDiscriminatorOid = null
        }

        val placeholder = Asn1ElementHolder.StructurePlaceholder(
            childSerializer = childSerializer,
            descriptor = descriptor,
            tagTemplate = tagTemplate,
        )
        buffer += placeholder
        return childSerializer
    }

    /** Balances the [beginStructure] depth increment. */
    override fun endStructure(descriptor: SerialDescriptor) {
        depthGuard.exit()
    }

    private fun consumePropertyContextOrNull(): DerPropertyContext? =
        pendingPropertyContext.also { pendingPropertyContext = null }

    internal fun appendElement(
        element: Asn1Element,
        tagTemplate: Asn1Element.Tag.Template? = null,
    ) {
        val taggedElement = tagTemplate?.let {
            if (!element.isAsn1NullElement()) {
                requireCompatibleConstructedBit(
                    element.tag.isConstructed, it, element::class.simpleName ?: "ASN.1 element"
                )
            }
            element.withImplicitTag(it)
        } ?: element
        buffer += Asn1ElementHolder.Element(taggedElement)
    }

    private fun requireRepresentableCollectionNull(context: DerPropertyContext) {
        if (!der.configuration.explicitNulls &&
            (context.ownerDescriptor.kind is StructureKind.LIST || context.ownerDescriptor.kind is StructureKind.MAP)
        ) {
            throw SerializationException(
                "Null collection elements cannot be omitted when explicitNulls=false; enable explicitNulls or reject the value"
            )
        }
    }

    private fun requireCompatibleConstructedBit(
        actual: Boolean,
        template: Asn1Element.Tag.Template,
        valueKind: String,
    ) {
        val requested = template.constructed ?: return
        if (requested != actual) {
            throw SerializationException(
                "@Asn1Tag constructed=$requested contradicts $valueKind constructed=$actual"
            )
        }
    }

    internal fun <T> encodeSingleElement(serializer: KSerializer<T>, value: T): Asn1Element {
        val child = DerEncoder(der, analysis, depthGuard)
        child.encodeSerializableValue(serializer, value)
        return child.encodeToTLV().singleOrNull()
            ?: throw SerializationException("${serializer.descriptor.serialName} must encode to exactly one ASN.1 element")
    }

    //exists to keep the below function
    internal fun encodeToTLV() = buffer.finalizeElements()

    private fun List<Asn1ElementHolder>.finalizeElements(): List<Asn1Element> = map(::finalizeElement)


    private fun finalizeElement(holder: Asn1ElementHolder): Asn1Element {

        return when (holder) {
            is Asn1ElementHolder.Element -> holder.element

            is Asn1ElementHolder.StructurePlaceholder -> {
                val childElements = holder.childSerializer.buffer.finalizeElements()
                val structureElement = when (holder.descriptor.asn1StructureTag) {
                    Asn1Element.Tag.SET -> if (holder.descriptor.sortSetChildren) {
                        Asn1Set(childElements)
                    } else {
                        Asn1CustomStructure(
                            childElements,
                            Asn1Element.Tag.SET.tagValue,
                            shouldBeSorted = true,
                        )
                    }

                    else -> Asn1Sequence(childElements)
                }
                holder.tagTemplate?.let {
                    if (childElements.isNotEmpty() && !holder.descriptor.isAsn1OctetStringEncapsulatedDescriptor()) {
                        requireCompatibleConstructedBit(true, it, "ASN.1 structure")
                    }
                    structureElement.withImplicitTag(it)
                } ?: structureElement
            }

        }
    }

    private fun appendNullElement(
        descriptor: SerialDescriptor,
        tagTemplate: Asn1Element.Tag.Template?,
    ) {
        val primitiveTaggedStructure = tagTemplate?.constructed == false && when (descriptor.kind) {
            is StructureKind.CLASS,
            is StructureKind.OBJECT,
            is StructureKind.LIST,
            is StructureKind.MAP -> true
            else -> false
        }
        appendElement(Asn1.Null(), tagTemplate.takeUnless { primitiveTaggedStructure })
    }
}
