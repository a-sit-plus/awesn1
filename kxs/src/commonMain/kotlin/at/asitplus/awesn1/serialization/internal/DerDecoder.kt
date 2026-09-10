// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(InternalAwesn1Api::class)

package at.asitplus.awesn1.serialization.internal


import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.*
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.awesn1.serialization.Asn1Serializable
import at.asitplus.awesn1.serialization.Der
import at.asitplus.awesn1.serialization.asn1Tag
import at.asitplus.awesn1.serialization.isAsn1BitString
import at.asitplus.awesn1.serialization.isAsn1OctetStringEncapsulatedDescriptor
import at.asitplus.awesn1.serialization.resolveAsn1TagTemplate
import kotlinx.serialization.*
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.AbstractDecoder
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.internal.AbstractPolymorphicSerializer
import kotlinx.serialization.modules.SerializersModule
import kotlin.time.Instant

private data class DerDecodeSlot(
    val property: DerPropertyContext,
    val isTrailing: Boolean,
    val couldBeAbsent: Boolean = false,
) {
    companion object {
        fun forProperty(context: DerPropertyContext, isTrailing: Boolean) = DerDecodeSlot(
            property = context,
            isTrailing = isTrailing,
        )

        fun standalone(descriptor: SerialDescriptor) = DerDecodeSlot(
            property = DerPropertyContext(
                ownerDescriptor = descriptor,
                index = 0,
                propertyDescriptor = descriptor,
                propertyAsn1Tag = descriptor.annotations.asn1Tag,
                propertyAsBitString = descriptor.isAsn1BitString,
                propertyName = descriptor.serialName,
            ),
            isTrailing = true,
        )
    }
}

private class DerElementCursor(
    private val elements: List<Asn1Element>,
) {
    var position: Int = 0
        private set

    val size: Int get() = elements.size
    val remaining: Int get() = size - position
    val isAtEnd: Boolean get() = position >= size

    fun currentOrNull(): Asn1Element? = elements.getOrNull(position)

    fun current(): Asn1Element = currentOrNull()
        ?: throw SerializationException("No ASN.1 element at index $position (have $size)")

    fun <T> consume(decode: (Asn1Element) -> T): T {
        val decoded = decode(current())
        position++
        return decoded
    }
}

internal data class DerDecodeHandoff(
    val inheritedPropertyTag: Asn1Tag? = null,
    val acceptWireTag: Boolean = false,
    val discriminatorOid: ObjectIdentifier? = null,
) {
    fun <T : Any> withSelection(selection: DerDecodeSelection<T>) = copy(
        acceptWireTag = selection.acceptWireTag,
        discriminatorOid = selection.discriminatorOid,
    )
}


@ExperimentalSerializationApi
/**
 * ASN.1 DER decoder used by [Der] format operations.
 *
 * This decoder supports:
 * - annotation-driven implicit tag override processing via [at.asitplus.awesn1.serialization.Asn1Tag]
 * - sealed CHOICE decoding via sealed polymorphism
 * - runtime ambiguity checks for nullable/optional class layouts
 * - lossless Kotlin [Set] decoding by rejecting duplicate elements instead of silently collapsing them
 */
class DerDecoder internal constructor(
    elements: List<Asn1Element>,
    override val der: Der,
    private val analysis: DerAnalysisContext = DerAnalysisContext(der.configuration.explicitNulls),
    // Shared across the whole decode so structural recursion is bounded. kotlinx.serialization's decode contract is
    // recursive descent (deserialize -> decodeSerializableElement -> deserialize -> ...), which the iterative raw
    // parser cannot flatten; this counter turns an unrecoverable StackOverflowError on a deeply nested recursive
    // type into a clean SerializationException. Every child decoder MUST receive this same instance.
    private val depthGuard: DerDepthGuard = DerDepthGuard(),
    private val polymorphicHandoff: DerDecodeHandoff = DerDecodeHandoff(),
) : AbstractDecoder(), at.asitplus.awesn1.serialization.DerDecoder {

    override val serializersModule get() = der.serializersModule

    private val cursor = DerElementCursor(elements)
    private var descriptorIndex = 0
    private var currentSlot: DerDecodeSlot? = null
    private val inlineHintState = DerInlineHintState()


    internal fun peekCurrentElementTagOrNull(): Asn1Element.Tag? = cursor.currentOrNull()?.tag
    internal fun peekCurrentElementOrNull(): Asn1Element? = cursor.currentOrNull()

    @Suppress("UNCHECKED_CAST")
    private fun <T> castDecoded(value: Any?): T = value as T

    @Suppress("UNCHECKED_CAST")
    private fun <T> nullDecoded(): T = null as T

    private fun decodeAsn1SerializableValue(
        serializer: Asn1Serializable<*, *>,
        processedElement: Asn1Element,
        expectedTag: Asn1Element.Tag?,
    ): Any = runWrappingAs(a = ::SerializationException) { when (processedElement) {
        is Asn1Primitive -> {
            @Suppress("UNCHECKED_CAST")
            val primitiveDecoder = serializer as? Asn1Decodable<Asn1Primitive, *>
                ?: throw SerializationException(
                    "Serializer ${serializer.descriptor.serialName} cannot decode ASN.1 primitive values"
                )
            primitiveDecoder.decodeFromTlv(processedElement, expectedTag)
        }

        is Asn1Structure -> {
            @Suppress("UNCHECKED_CAST")
            val structureDecoder = serializer as? Asn1Decodable<Asn1Structure, *>
                ?: throw SerializationException(
                    "Serializer ${serializer.descriptor.serialName} cannot decode ASN.1 structure values"
            )
            structureDecoder.decodeFromTlv(processedElement, expectedTag)
        }
    } }

    /**
     * Decodes the current element in an isolated child decoder context.
     *
     * @throws SerializationException if no current element exists or decoding fails for [deserializer]
     */
    @Throws(SerializationException::class)
    internal fun <T> decodeCurrentElementWith(deserializer: DeserializationStrategy<T>): T =
        decodeCurrentElementWith(deserializer, polymorphicHandoff)

    internal fun <T : Any> decodeCurrentElementWith(selection: DerDecodeSelection<T>): T =
        decodeCurrentElementWith(selection.deserializer, polymorphicHandoff.withSelection(selection))

    private fun <T> decodeCurrentElementWith(
        deserializer: DeserializationStrategy<T>,
        handoff: DerDecodeHandoff,
    ): T = cursor.consume { current ->
        val isolated = DerDecoder(
            elements = listOf(current),
            der = der,
            analysis = analysis,
            depthGuard = depthGuard,
            polymorphicHandoff = handoff,
        )
        isolated.initializeStandalonePropertyState(deserializer.descriptor)
        isolated.decodeSerializableValue(deserializer)
    }

    @OptIn(ExperimentalSerializationApi::class)
    override fun decodeInline(descriptor: SerialDescriptor): Decoder {
        if (currentSlot == null) {
            initializeStandalonePropertyState(descriptor)
        }
        inlineHintState.captureInlineHintsFrom(descriptor)
        return this
    }

    /**
     * Begins structure decoding by materializing a child decoder for structure children.
     *
     * @throws SerializationException if a structure descriptor is mapped to a non-structure ASN.1 element
     */
    override fun beginStructure(descriptor: SerialDescriptor): CompositeDecoder {

        // Bound structural recursion before descending another level (see [DerDepthGuard]). Balanced by the
        // matching endStructure() decrement.
        depthGuard.enter(der.configuration.maxNestingDepth, descriptor.serialName)

        return cursor.consume { element ->
            when (descriptor.kind) {
                is StructureKind.CLASS,
                is StructureKind.OBJECT,
                is StructureKind.LIST,
                is StructureKind.MAP -> {
                    if (element is Asn1Structure || element is Asn1EncapsulatingOctetString ||
                        element is Asn1Primitive &&
                        (descriptor.isAsn1OctetStringEncapsulatedDescriptor() || element.contentLength == 0)
                    ) {
                        val children = when (element) {
                            is Asn1Structure -> element.children
                            is Asn1EncapsulatingOctetString -> element.children
                            is Asn1Primitive -> Asn1Element.parseAll(element.content)
                        }

                        val effectiveChildren = children.withoutPendingDiscriminatorOid()

                        DerDecoder(
                            effectiveChildren,
                            der = der,
                            analysis = analysis,
                            depthGuard = depthGuard,
                        )
                    } else {
                        throw SerializationException(
                            "Expected an ASN.1 structure for ${descriptor.serialName}, " +
                                    "but got ${element::class.simpleName}"
                        )
                    }
                }

                is PolymorphicKind -> {
                    val children = element.asStructure().children
                    val effectiveChildren = children.withoutPendingDiscriminatorOid()

                    DerDecoder(
                        effectiveChildren,
                        der = der,
                        analysis = analysis,
                        depthGuard = depthGuard,
                    )
                }

                // Primitive wrappers (CHOICE, ENUM, etc.) keep using the same instance
                else -> this

            }
        }
    }

    /** Balances the [beginStructure] depth increment. */
    override fun endStructure(descriptor: SerialDescriptor) {
        depthGuard.exit()
    }

    /**
     * Resolves next property index and validates optional/nullable layout constraints.
     *
     * @throws SerializationException if class/object layout is ambiguous or trailing input remains unexpectedly
     */
    @Throws(SerializationException::class)
    override fun decodeElementIndex(descriptor: SerialDescriptor): Int {
        return when (descriptor.kind) {
            is StructureKind.CLASS, is StructureKind.OBJECT -> {
                if (descriptorIndex == 0) {
                    analysis.validateOptionalLayout(descriptor)
                }
                if (descriptorIndex >= descriptor.elementsCount) {
                    if (!cursor.isAtEnd) {
                        throw SerializationException(
                            "Too many ASN.1 elements for ${descriptor.serialName}: " +
                                    "all ${descriptor.elementsCount} properties decoded, " +
                                    "but ${cursor.remaining} element(s) remain"
                        )
                    }
                    return CompositeDecoder.DECODE_DONE
                }
                val currentDescriptorIndex = descriptorIndex++
                applyCurrentPropertyContext(
                    ownerDescriptor = descriptor,
                    propertyIndex = currentDescriptorIndex,
                    isTrailing = currentDescriptorIndex >= descriptor.elementsCount - 1,
                )
                val propertyContext = requireNotNull(currentSlot).property
                val nullEncodingAnalysis = analysis.analyzeNullable(
                    descriptor = propertyContext.propertyDescriptor,
                    propertyAsn1Tag = propertyContext.propertyAsn1Tag,
                    propertyAsBitString = propertyContext.propertyAsBitString,
                )
                if (descriptor.isElementOptional(currentDescriptorIndex) &&
                    !propertyContext.propertyDescriptor.isNullable &&
                    !cursor.isAtEnd
                ) {
                    val actualTag = cursor.current().tag
                    val expectedTags = analysis.possibleLeadingTags(
                        descriptor = propertyContext.propertyDescriptor,
                        propertyAsn1Tag = propertyContext.propertyAsn1Tag,
                        propertyAsBitString = propertyContext.propertyAsBitString,
                    )
                    if (expectedTags is Asn1LeadingTagsResolution.Exact &&
                        actualTag !in expectedTags.tags &&
                        !(nullEncodingAnalysis.encodeNullEnabled && cursor.current().isAsn1NullElement())
                    ) {
                        return decodeElementIndex(descriptor)
                    }
                }
                val couldBeAbsent = propertyContext.propertyDescriptor.isNullable &&
                        !nullEncodingAnalysis.encodeNullEnabled
                currentSlot = requireNotNull(currentSlot).copy(couldBeAbsent = couldBeAbsent)

                if (cursor.isAtEnd && !couldBeAbsent) {
                    CompositeDecoder.DECODE_DONE
                } else {
                    currentDescriptorIndex
                }
            }

            else -> {
                // list-like descriptors always have elementCount = 1 because
                // they can never know how long the list actually is
                val max = maxOf(descriptor.elementsCount, cursor.size)
                if (cursor.position >= max) return CompositeDecoder.DECODE_DONE

                if (cursor.isAtEnd) return CompositeDecoder.DECODE_DONE
                applyCurrentPropertyContext(
                    ownerDescriptor = descriptor,
                    propertyIndex = cursor.position,
                    isTrailing = true,
                    safePropertyNameLookup = true,
                )
                if (!cursor.isAtEnd) cursor.position else CompositeDecoder.DECODE_DONE
            }
        }
    }

    /**
     * Primitive decode path for descriptors consumed through `decodeValue`.
     *
     * @throws SerializationException on unsupported descriptor shapes or ASN.1 tag/value mismatches
     */
    override fun decodeValue(): Any {
        val inlineAnnotation = inlineHintState.consume().tag
        val propertyContext = requireNotNull(currentSlot).property
        val propertyDescriptor = propertyContext.propertyDescriptor

        return cursor.consume { processedElement ->
            val effectiveDescriptor =
                if (propertyDescriptor.isInline && propertyDescriptor.elementsCount == 1) {
                    propertyDescriptor.unwrapInlineDescriptorForAsn1()
                } else {
                    propertyDescriptor
                }

            val expectedTag = validateAndResolveImplicitTagOverride(
                actualTag = processedElement.tag,
                inlineAsn1Tag = inlineAnnotation,
                propertyAsn1Tag = propertyContext.propertyAsn1Tag,
                classAsn1Tag = effectiveDescriptor.asn1Tag,
            )

            val decoded = when (effectiveDescriptor.kind) {
                PolymorphicKind.OPEN -> throw SerializationException(
                    "Open polymorphic decoding is not supported via primitive decode path for ${effectiveDescriptor.serialName}. " +
                            "Register an ASN.1 open-polymorphic serializer in DER { serializersModule = ... } " +
                            "via polymorphicByTag(...) or polymorphicByOid(...)."
                )

                PolymorphicKind.SEALED -> throw SerializationException(
                    "Sealed polymorphic decoding is not supported via primitive decode path for ${effectiveDescriptor.serialName}. " +
                            "ASN.1 CHOICE is supported for sealed types in composite decoding paths."
                )

                PrimitiveKind.BOOLEAN -> processedElement.asPrimitive()
                    .decodeToBoolean(expectedTag ?: Asn1Element.Tag.BOOL)

                PrimitiveKind.BYTE -> processedElement.asPrimitive()
                    .decodeToInt(expectedTag ?: Asn1Element.Tag.INT)
                    .let {
                        if (propertyDescriptor.inlineChainContains("kotlin.UByte")) it.toStrictUByteBacking()
                        else it.toStrictByte()
                    }

                PrimitiveKind.CHAR -> processedElement.asPrimitive().decodeString(expectedTag)
                    .also { if (it.length != 1) throw SerializationException("String is not a char") }[0]

                PrimitiveKind.DOUBLE -> processedElement.asPrimitive()
                    .decodeToDouble(expectedTag ?: Asn1Element.Tag.REAL)

                PrimitiveKind.FLOAT -> processedElement.asPrimitive()
                    .decodeToFloat(expectedTag ?: Asn1Element.Tag.REAL)

                PrimitiveKind.INT -> if (propertyDescriptor.inlineChainContains("kotlin.UInt")) {
                    processedElement.asPrimitive().decodeToUInt(expectedTag ?: Asn1Element.Tag.INT).toInt()
                } else {
                    processedElement.asPrimitive().decodeToInt(expectedTag ?: Asn1Element.Tag.INT)
                }

                PrimitiveKind.LONG -> if (propertyDescriptor.inlineChainContains("kotlin.ULong")) {
                    processedElement.asPrimitive().decodeToULong(expectedTag ?: Asn1Element.Tag.INT).toLong()
                } else {
                    processedElement.asPrimitive().decodeToLong(expectedTag ?: Asn1Element.Tag.INT)
                }

                PrimitiveKind.SHORT -> processedElement.asPrimitive()
                    .decodeToInt(expectedTag ?: Asn1Element.Tag.INT)
                    .let {
                        if (propertyDescriptor.inlineChainContains("kotlin.UShort")) it.toStrictUShortBacking()
                        else it.toStrictShort()
                    }

                PrimitiveKind.STRING -> processedElement.asPrimitive().decodeString(expectedTag)
                SerialKind.ENUM -> processedElement.asPrimitive()
                    .decodeToEnumOrdinal(expectedTag ?: Asn1Element.Tag.ENUM)

                else -> throw SerializationException(
                    "Unsupported descriptor kind ${propertyDescriptor.kind} for ${effectiveDescriptor.serialName} in decodeValue(). " +
                            "Provide a custom serializer or use a supported ASN.1 mapping shape."
                )
            } as Any
            decoded
        }
    }

    @OptIn(InternalSerializationApi::class)
    /**
     * Handles nullable/absent semantics before delegating to the main decode pipeline.
     *
     * @throws SerializationException if nullable omission/encoding is undecidable or invalid for current property
     */
    override fun <T : Any?> decodeSerializableValue(
        deserializer: DeserializationStrategy<T>,
        previousValue: T?
    ): T {

        val slot = currentSlot
        val propertyContext = slot?.property
        val nullableCouldBeAbsent = slot?.couldBeAbsent == true
        val descriptorNullEncodingAnalysis = analysis.analyzeNullable(deserializer.descriptor)
        if (nullableCouldBeAbsent) {
            val nullableProperty = requireNotNull(propertyContext)
            val pendingInlineHints = inlineHintState.peek()
            if (cursor.isAtEnd) {
                return nullDecoded()
            }

            val openSerializer = resolveOpenPolymorphicAsn1SerializerOrNull(deserializer, serializersModule)
            val tagDispatched = openSerializer is Asn1TagDiscriminatedOpenPolymorphicSerializer<*>
            when (val expectedLeadingTags = analysis.possibleLeadingTags(
                descriptor = openSerializer?.descriptor ?: nullableProperty.propertyDescriptor,
                propertyAsn1Tag = nullableProperty.propertyAsn1Tag.takeUnless { tagDispatched },
                inlineAsn1Tag = pendingInlineHints.tag,
                propertyAsBitString = nullableProperty.propertyAsBitString,
                inlineAsBitString = pendingInlineHints.asBitString,
            )) {
                is Asn1LeadingTagsResolution.Exact -> {
                    val actualTag = cursor.current().tag
                    if (actualTag !in expectedLeadingTags.tags) {
                        return nullDecoded()
                    }
                }

                Asn1LeadingTagsResolution.UnknownInfer -> {
                    if (!slot.isTrailing) {
                        throw SerializationException(
                            undecidableAsn1NullableDecodingMessage(
                                ownerSerialName = nullableProperty.ownerSerialName,
                                propertyName = nullableProperty.propertyName
                                    ?: nullableProperty.propertyDescriptor.serialName,
                                propertyIndex = nullableProperty.index,
                                reason = expectedLeadingTags.reason(),
                            )
                        )
                    }
                }
            }
        }
        val currentAnnotatedElement = cursor.current()
        if (currentAnnotatedElement.isAsn1NullElement() &&
            deserializer.descriptor.serialName.removeSuffix("?") != ASN1_DESCRIPTOR_ELEMENT_TREE
        ) {
            val propertyDescriptorEncodesNull = propertyContext != null &&
                    analysis.analyzeNullable(
                        descriptor = propertyContext.propertyDescriptor,
                        propertyAsn1Tag = propertyContext.propertyAsn1Tag,
                        propertyAsBitString = propertyContext.propertyAsBitString,
                    ).encodeNullEnabled
            if (!propertyDescriptorEncodesNull && !descriptorNullEncodingAnalysis.encodeNullEnabled) {
                throw SerializationException("Null value found, but target value should not have been present!")
            }
            return cursor.consume { nullDecoded() }
        }
        return decodeSerializableValue(deserializer)
    }

    @OptIn(InternalSerializationApi::class)
    /**
     * Main serialization pipeline for DER decoding.
     *
     * @throws SerializationException if serializer/tag/nullability/polymorphism constraints are violated
     */
    @Throws(SerializationException::class)
    override fun <T> decodeSerializableValue(deserializer: DeserializationStrategy<T>): T {
        if (cursor.size == 0 && deserializer.descriptor.isNullable) return nullDecoded()
        val propertyContext = currentSlot?.property
        val pendingInlineHints = inlineHintState.peek()
        val pendingPropertyTag = polymorphicHandoff.inheritedPropertyTag ?: propertyContext?.propertyAsn1Tag
        val pendingNullAnalysis = analysis.analyzeNullable(
            descriptor = propertyContext?.propertyDescriptor ?: deserializer.descriptor,
            propertyAsn1Tag = pendingPropertyTag,
            inlineAsn1Tag = pendingInlineHints.tag,
            propertyAsBitString = propertyContext?.propertyAsBitString == true,
            inlineAsBitString = pendingInlineHints.asBitString,
        )
        val pendingElement = cursor.current()
        if (pendingNullAnalysis.matchesEncodedNull(pendingElement)) {
            if (!pendingElement.isAsn1NullElement()) {
                val template = resolveAsn1TagTemplate(
                    inlineAsn1Tag = pendingInlineHints.tag,
                    propertyAsn1Tag = pendingPropertyTag,
                    classAsn1Tag = deserializer.descriptor.asn1Tag,
                )
                if (template != null) {
                    val expectedTag = Asn1Element.Tag(
                        template.tagValue,
                        template.constructed ?: pendingElement.tag.isConstructed,
                        template.tagClass ?: TagClass.CONTEXT_SPECIFIC,
                    )
                    if (pendingElement.tag.tagValue != expectedTag.tagValue ||
                        pendingElement.tag.tagClass != expectedTag.tagClass
                    ) {
                        throw SerializationException(Asn1TagMismatchException(expectedTag, pendingElement.tag))
                    }
                }
            }
            inlineHintState.clear()
            return cursor.consume { nullDecoded() }
        }
        if (deserializer.descriptor.isInline) {
            // Let the framework do its inline-class magic **before consuming pending inline hints.**
            return deserializer.deserialize(this)
        }
        val currentAnnotatedElement = cursor.current()
        val inlineHints = inlineHintState.consume()
        val effectivePropertyAsn1Tag = polymorphicHandoff.inheritedPropertyTag ?: propertyContext?.propertyAsn1Tag
        val valueSite = analysis.prepareValue(
            descriptor = deserializer.descriptor,
            nullAnalysisDescriptor = propertyContext?.propertyDescriptor ?: deserializer.descriptor,
            inlineHints = inlineHints,
            propertyContext = propertyContext,
            propertyAsn1Tag = effectivePropertyAsn1Tag,
            propertyAsBitString = propertyContext?.propertyAsBitString == true,
        )
        valueSite.validateSerializerAnnotations(
            // Asn1OctetString has a concrete wire representation despite sharing the opaque element descriptor.
            allowTaggedRawElementDescriptor = deserializer == Asn1OctetStringFallbackBase64Serializer,
            isGenericAsn1StringSerializer = deserializer == Asn1String.Companion,
        )
        valueSite.requireUnambiguousNull()

        resolveOpenPolymorphicAsn1SerializerOrNull(deserializer, serializersModule)?.let { openSerializer ->
            if (openSerializer.descriptor == deserializer.descriptor) {
                throw SerializationException(
                    "Open polymorphism for ${deserializer.descriptor.serialName} resolved to itself. " +
                            "Register a concrete ASN.1 open-polymorphic serializer in DER { serializersModule = ... }."
                )
            }
            val inheritedPropertyTag =
                if (openSerializer is Asn1TagDiscriminatedOpenPolymorphicSerializer<*>) null
                else polymorphicHandoff.inheritedPropertyTag
                    ?: valueSite.inlineHints.tag
                    ?: valueSite.propertyContext?.propertyAsn1Tag
            @Suppress("UNCHECKED_CAST")
            return decodeCurrentElementWith(
                openSerializer as DeserializationStrategy<T>,
                DerDecodeHandoff(inheritedPropertyTag = inheritedPropertyTag),
            )
        }

        if (deserializer.descriptor.kind is PolymorphicKind.OPEN && deserializer is AbstractPolymorphicSerializer<*>) {
            throw SerializationException(
                "Open polymorphism for ${deserializer.descriptor.serialName} requires an ASN.1 serializer " +
                        "registered in DER { serializersModule = ... } via polymorphicByTag(...) " +
                        "or polymorphicByOid(...)."
            )
        }

        if (deserializer is SealedClassSerializer<*>) {
            return decodeChoiceSerializableValue(deserializer, currentAnnotatedElement, valueSite.inlineHints.tag)
        }

        return decodeConcreteValue(deserializer, currentAnnotatedElement, valueSite)
    }

    private fun <T> decodeConcreteValue(
        deserializer: DeserializationStrategy<T>,
        currentAnnotatedElement: Asn1Element,
        valueSite: DerValueSite,
    ): T {
        val processedElement = if (
            polymorphicHandoff.acceptWireTag &&
            currentAnnotatedElement is Asn1Primitive &&
            (deserializer.descriptor.kind is StructureKind.CLASS || deserializer.descriptor.kind is StructureKind.OBJECT)
        ) {
            Asn1CustomStructure(
                children = Asn1Element.parseAll(currentAnnotatedElement.content).toMutableList(),
                tag = currentAnnotatedElement.tag.tagValue,
                tagClass = currentAnnotatedElement.tag.tagClass,
                sortChildren = false,
                shouldBeSorted = false,
            )
        } else currentAnnotatedElement
        val expectedTag = validateAndResolveImplicitTagOverride(
            actualTag = processedElement.tag,
            inlineAsn1Tag = valueSite.inlineHints.tag,
            propertyAsn1Tag = valueSite.effectivePropertyTag,
            classAsn1Tag = valueSite.descriptor.asn1Tag,
        )
        when (deserializer.descriptor.serialName.removeSuffix("?")) {
            ASN1_DESCRIPTOR_ELEMENT_TREE -> {
                depthGuard.ensureElementTreeFits(
                    processedElement, der.configuration.maxNestingDepth, deserializer.descriptor.serialName
                )
                return cursor.consume {
                    if (deserializer == Asn1OctetStringFallbackBase64Serializer) {
                        if (expectedTag == null && processedElement.tag != Asn1Element.Tag.OCTET_STRING) {
                            throw SerializationException(
                                Asn1TagMismatchException(Asn1Element.Tag.OCTET_STRING, processedElement.tag)
                            )
                        }
                        castDecoded(Asn1OctetString(processedElement.asPrimitive().content))
                    } else {
                        require(deserializer is Asn1ElementFallbackBase64SerializerBase<*>) {
                            "Reserved SerialName for Asn1ElementFallbackBase64SerializerBase reused by: ${deserializer::class.simpleName}"
                        }
                        castDecoded(deserializer.decodeFromAsn1Element(processedElement))
                    }
                }
            }
        }

        if (deserializer is Asn1Serializable<*, *>) {
            depthGuard.ensureElementTreeFits(
                processedElement, der.configuration.maxNestingDepth, deserializer.descriptor.serialName
            )
            return cursor.consume {
                castDecoded(decodeAsn1SerializableValue(deserializer, processedElement, expectedTag))
            }
        }

        if (deserializer.descriptor.isKotlinTimeInstantDescriptor()) {
            val primitive = processedElement as? Asn1Primitive
                ?: throw SerializationException(
                    "Expected ASN.1 primitive for kotlin.time.Instant, but got ${processedElement::class.simpleName}"
                )
            return cursor.consume {
                castDecoded(primitive.decodeInstantWithOptionalImplicitTag(expectedTag))
            }
        }

        // Tag-check for explicitly / implicitly tagged primitives
        val tagToValidate = expectedTag ?: if (!polymorphicHandoff.acceptWireTag) {
            ByteArrayShapePolicy.defaultTagForDescriptor(deserializer.descriptor, valueSite.byteArrayShape)
        } else null

        tagToValidate?.let { expected ->
            if (processedElement.tag != expected) {
                throw SerializationException(Asn1TagMismatchException(expected, processedElement.tag))
            }
        }
        if (deserializer == ByteArraySerializer()) {
            return cursor.consume {
                castDecoded(
                    ByteArrayShapePolicy.decodeByteArray(
                        primitive = processedElement.asPrimitive(),
                        shape = valueSite.byteArrayShape,
                        tagToValidate = tagToValidate,
                    )
                )
            }
        }

        if (deserializer.descriptor.kind == SerialKind.ENUM) {
            val ordinal = processedElement.asPrimitive()
                .decodeToEnumOrdinal(expectedTag ?: Asn1Element.Tag.ENUM)
                .let {
                    if (it < 0) throw SerializationException("Negative ordinal $it cannot be auto-mapped to an enum value")
                    if (it > Int.MAX_VALUE.toLong()) throw SerializationException("Ordinal $it too large!")
                    it.toInt()
                }
            val enumDecoder = object : AbstractDecoder() {
                override val serializersModule: SerializersModule = this@DerDecoder.serializersModule
                override fun decodeEnum(enumDescriptor: SerialDescriptor): Int = ordinal
                override fun decodeElementIndex(descriptor: SerialDescriptor): Int = CompositeDecoder.DECODE_DONE
            }
            return cursor.consume { deserializer.deserialize(enumDecoder) }
        }

        // (3) Primitive kinds → let deserializer consume primitive decoder APIs.
        // This preserves custom primitive-wrapper serializers (e.g. value classes / wrappers
        // with PrimitiveSerialDescriptor) instead of short-circuiting to raw primitive values.
        if (deserializer.descriptor.kind is PrimitiveKind) {
            if (currentSlot == null) {
                initializeStandalonePropertyState(deserializer.descriptor)
            }
            val primitiveSlot = requireNotNull(currentSlot)
            if (primitiveSlot.property.propertyAsn1Tag == null) {
                currentSlot = primitiveSlot.copy(
                    property = primitiveSlot.property.copy(
                        propertyAsn1Tag = deserializer.descriptor.annotations.asn1Tag
                    )
                )
            }
            return deserializer.deserialize(this)
        }


        return cursor.consume {
            val childDecoder = DerDecoder(
                elements = mutableListOf(processedElement),
                der = der,
                analysis = analysis,
                depthGuard = depthGuard,
                polymorphicHandoff = DerDecodeHandoff(discriminatorOid = polymorphicHandoff.discriminatorOid),
            )
            val value = deserializer.deserialize(childDecoder)
            if (deserializer.descriptor.isKotlinSetDescriptor &&
                value is Set<*> &&
                value.size != processedElement.asStructure().children.size
            ) {
                throw SerializationException(
                    "Duplicate elements cannot be decoded into ${deserializer.descriptor.serialName} without data loss"
                )
            }
            if (deserializer.descriptor.kind is StructureKind.MAP &&
                value is Map<*, *> &&
                value.size * 2 != processedElement.asStructure().children.size
            ) {
                throw SerializationException(
                    "Duplicate keys cannot be decoded into ${deserializer.descriptor.serialName} without data loss"
                )
            }
            value
        }
    }

    private fun initializeStandalonePropertyState(descriptor: SerialDescriptor) {
        currentSlot = DerDecodeSlot.standalone(descriptor)
    }

    private fun List<Asn1Element>.withoutPendingDiscriminatorOid(): List<Asn1Element> {
        val oid = polymorphicHandoff.discriminatorOid ?: return this
        val index = indexOfFirst { element ->
            element is Asn1Primitive && element.tag == Asn1Element.Tag.OID &&
                    runCatching { element.readOid() }.getOrNull() == oid
        }
        return if (index < 0) this else filterIndexed { childIndex, _ -> childIndex != index }
    }

    private fun applyCurrentPropertyContext(
        ownerDescriptor: SerialDescriptor,
        propertyIndex: Int,
        isTrailing: Boolean,
        safePropertyNameLookup: Boolean = false,
    ) {
        val context = try {
            (ownerDescriptor to propertyIndex).toDerPropertyContext(
                safePropertyNameLookup = safePropertyNameLookup
            )
        } catch (t: IndexOutOfBoundsException) {
            throw SerializationException(t.toString())
        }
        currentSlot = DerDecodeSlot.forProperty(context, isTrailing)
    }

    @OptIn(InternalSerializationApi::class)
    @Suppress("UNCHECKED_CAST")
    /**
     * Decodes sealed-polymorphic CHOICE values by tag-based arm selection.
     *
     * @throws SerializationException if CHOICE descriptors/arms cannot be resolved or matched
     */
    @Throws(SerializationException::class)
    private fun <T> decodeChoiceSerializableValue(
        deserializer: SealedClassSerializer<*>,
        currentAnnotatedElement: Asn1Element,
        inlineAnnotation: Asn1Tag?,
    ): T {
        val sealedSerializer = deserializer as SealedClassSerializer<Any>

        rejectAsn1TagOnChoice(
            choiceSerialName = deserializer.descriptor.serialName,
            inlineAsn1Tag = inlineAnnotation,
            propertyAsn1Tag = currentSlot?.property?.propertyAsn1Tag,
            classAsn1Tag = deserializer.descriptor.asn1Tag,
        )
        val alternativesDescriptor = deserializer.descriptor.findLikelySealedAlternativesDescriptor()
            ?: throw SerializationException(
                "Could not inspect sealed CHOICE alternatives for ${deserializer.descriptor.serialName}"
            )
        val dispatch = buildSealedChoiceDispatch<Any>(
            ownerSerialName = deserializer.descriptor.serialName,
            alternativesDescriptor = alternativesDescriptor,
            resolveSerializerByName = { serialName ->
                sealedSerializer.findPolymorphicSerializerOrNull(this, serialName) as? KSerializer<out Any>
            },
        )
        val selected = dispatch.serializerForDecodeOrNull(currentAnnotatedElement.tag)
            ?: throw Asn1ChoiceNoMatchingAlternativeException(
                "No CHOICE alternative of ${deserializer.descriptor.serialName} matches tag ${currentAnnotatedElement.tag}"
            )

        return decodeCurrentElementWith(selected as DeserializationStrategy<T>)
    }

}

/**
 * Guards against deep structural nesting [DerDecoder]/[DerEncoder] and all of its
 * child encoders/decoders. [enter] is called once per `beginStructure` (a descent into a nested structure) and
 * balanced by [exit] in `endStructure`, so [depth] reflects the current live nesting depth. When it would exceed the
 * configured `maxNestingDepth`, [enter] throws a catchable [SerializationException] before stack exhaustion, provided
 * the configured limit fits the runtime's actual stack. A guard is needed because kotlinx.serialization's encode/decode
 * contract is recursive descent through `serialize`/`deserialize` frames the format cannot flatten or trampoline.
 */
internal class DerDepthGuard(private var depth: Int = 0) {
    fun enter(maxNestingDepth: Int, serialName: String) {
        depth++
        if (depth > maxNestingDepth) {
            throw SerializationException(
                "ASN.1 nesting depth exceeded the configured maxNestingDepth=$maxNestingDepth while " +
                        "processing '$serialName'. This usually means a recursive @Serializable type is being " +
                        "encoded/decoded at extreme depth; reduce the nesting or raise maxNestingDepth within its " +
                        "supported range."
            )
        }
    }

    fun exit() {
        depth--
    }

    fun ensureElementTreeFits(element: Asn1Element, maxNestingDepth: Int, serialName: String) {
        val pending = ArrayDeque<Pair<Asn1Element, Int>>()
        pending += element to depth
        while (pending.isNotEmpty()) {
            val (current, parentDepth) = pending.removeFirst()
            val children = when (current) {
                is Asn1Structure -> current.children
                is Asn1EncapsulatingOctetString -> current.children
                else -> continue
            }
            val currentDepth = parentDepth + 1
            if (currentDepth > maxNestingDepth) {
                throw SerializationException(
                    "ASN.1 nesting depth exceeded the configured maxNestingDepth=$maxNestingDepth while " +
                            "processing '$serialName'."
                )
            }
            children.forEach { pending += it to currentDepth }
        }
    }
}

private class Asn1ChoiceNoMatchingAlternativeException(message: String) : SerializationException(message)

/**
 * Decodes ASN.1 TIME content into [Instant], optionally under an implicit tag override.
 *
 * @throws SerializationException if content is neither UTCTime nor GeneralizedTime
 */
@Throws(SerializationException::class)
private fun Asn1Primitive.decodeInstantWithOptionalImplicitTag(expectedTag: Asn1Element.Tag?): Instant {
    if (expectedTag == null) return decodeToInstant()

    if (expectedTag == Asn1Element.Tag.TIME_UTC) {
        return catchingUnwrapped { Instant.decodeUtcTimeFromAsn1ContentBytes(content) }.getOrElse {
            throw SerializationException(it)
        }
    }

    if (expectedTag == Asn1Element.Tag.TIME_GENERALIZED) {
        return catchingUnwrapped { Instant.decodeGeneralizedTimeFromAsn1ContentBytes(content) }.getOrElse {
            throw SerializationException(it)
        }
    }

    val utc = catchingUnwrapped { Instant.decodeUtcTimeFromAsn1ContentBytes(content) }.getOrNull()
    if (utc != null) return utc

    val generalized = catchingUnwrapped { Instant.decodeGeneralizedTimeFromAsn1ContentBytes(content) }.getOrNull()
    if (generalized != null) return generalized

    throw SerializationException(
        "Failed to decode implicitly tagged ASN.1 TIME for kotlin.time.Instant: " +
                "content is neither UTCTime nor GeneralizedTime"
    )
}

/**
 * Decodes ASN.1 string content while honoring optional implicit tag override.
 *
 * @throws SerializationException if tag does not match expected string/override tag
 */
@Throws(SerializationException::class)
private fun Asn1Primitive.decodeString(implicitTagOverride: Asn1Element.Tag?): String =
    if (implicitTagOverride == null) {
        when (tag) {
            Asn1Element.Tag.STRING_UTF8,
            Asn1Element.Tag.STRING_BMP,
            Asn1Element.Tag.STRING_NUMERIC,
            Asn1Element.Tag.STRING_T61,
            Asn1Element.Tag.STRING_VISIBLE,
            Asn1Element.Tag.STRING_UNIVERSAL,
            Asn1Element.Tag.STRING_PRINTABLE,
            Asn1Element.Tag.STRING_IA5,
                -> when (tag) {
                    Asn1Element.Tag.STRING_BMP -> decodeToBmpString().value
                    Asn1Element.Tag.STRING_UNIVERSAL -> decodeToUniversalString().value
                    Asn1Element.Tag.STRING_T61 -> decodeToTeletextString().value
                    else -> decodeToString()
                }

            else -> throw SerializationException(Asn1TagMismatchException(Asn1Element.Tag.STRING_UTF8, tag))
        }
    } else {
        if (tag != implicitTagOverride) throw SerializationException(Asn1TagMismatchException(implicitTagOverride, tag))
        String.decodeFromAsn1ContentBytes(content)
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
