// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(InternalAwesn1Api::class)
@file:Suppress("NOTHING_TO_INLINE")

package at.asitplus.awesn1.serialization.internal


import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.*
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.awesn1.serialization.Asn1Serializable
import at.asitplus.awesn1.serialization.Der
import at.asitplus.awesn1.serialization.asn1Tag
import at.asitplus.awesn1.serialization.isAsn1OctetStringEncapsulatedDescriptor
import kotlinx.serialization.*
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.AbstractDecoder
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.internal.AbstractPolymorphicSerializer
import kotlinx.serialization.modules.SerializersModule

private data class DerDecodeSlot(
    val descriptor: SerialDescriptor? = null,
    val property: DerPropertyContext? = null,
    val isTrailing: Boolean = false,
    val couldBeAbsent: Boolean = false,
    val possibleLeadingTags: Asn1LeadingTagsResolution = Asn1LeadingTagsResolution.UnknownInfer,
) {
    companion object {
        /*single call site; code is more legible like that and inline saves a stack frame*/
        inline fun forProperty(
            context: DerPropertyContext,
            isTrailing: Boolean,
            couldBeAbsent: Boolean,
            possibleLeadingTags: Asn1LeadingTagsResolution = Asn1LeadingTagsResolution.UnknownInfer,
        ) = DerDecodeSlot(
            descriptor = context.propertyDescriptor,
            property = context,
            isTrailing = isTrailing,
            couldBeAbsent = couldBeAbsent,
            possibleLeadingTags = possibleLeadingTags,
        )

        fun standalone(descriptor: SerialDescriptor) = DerDecodeSlot(
            descriptor = descriptor,
            isTrailing = true,
        )
    }
}

/*internal only for inlining*/
internal class DerElementCursor(
    private val elements: List<Asn1Element>,
) {
    var position: Int = 0
        private set

    val size: Int get() = elements.size
    val remaining: Int get() = size - position
    val isAtEnd: Boolean get() = position >= size

    /*single call site; code is more legible like that and inline saves a stack frame*/
    inline fun currentOrNull(): Asn1Element? = elements.getOrNull(position)

    fun current(): Asn1Element = currentOrNull()
        ?: throw SerializationException("No ASN.1 element at index $position (have $size)")

    fun take(): Asn1Element = current().also { position++ }

    /*single call site; code is more legible like that and inline saves a stack frame*/
    inline fun advance() {
        val _ = current()
        position++
    }

    /*single call site; code is more legible like that and inline saves a stack frame*/
    inline fun <T> consume(decode: (Asn1Element) -> T): T {
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
    /*single call site; code is more legible like that and inline saves a stack frame*/
    inline fun <T : Any> withSelection(selection: DerDecodeSelection<T>) = copy(
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
    private var currentSlot = DerDecodeSlot()
    private val inlineHintState = DerInlineHintState()


    /*single call site; code is more legible like that and inline saves a stack frame*/
    internal inline fun peekCurrentElementTagOrNull(): Asn1Element.Tag? = cursor.currentOrNull()?.tag
    /*single call site; code is more legible like that and inline saves a stack frame*/
    internal inline fun peekCurrentElementOrNull(): Asn1Element? = cursor.currentOrNull()

    @Suppress("UNCHECKED_CAST")
    private fun <T> castDecoded(value: Any?): T = value as T

    @Suppress("UNCHECKED_CAST")
    private fun <T> nullDecoded(): T = null as T

    /**
     * Decodes the current element in an isolated child decoder context.
     *
     * @throws SerializationException if no current element exists or decoding fails for [deserializer]
     */
    @Throws(SerializationException::class)
    /*single call site; code is more legible like that and inline saves a stack frame*/
    internal inline fun <T> decodeCurrentElementWith(deserializer: DeserializationStrategy<T>): T =
        decodeCurrentElementWith(deserializer, polymorphicHandoff)

    /*single call site; code is more legible like that and inline saves a stack frame*/
    internal inline fun <T : Any> decodeCurrentElementWith(selection: DerDecodeSelection<T>): T =
        decodeCurrentElementWith(selection.deserializer, polymorphicHandoff.withSelection(selection))

    /*single call site; code is more legible like that and inline saves a stack frame*/
    private inline fun <T> decodeCurrentElementWith(
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
        currentSlot = currentSlot.copy(descriptor = descriptor)
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
                val shape = requireNotNull(analysis.validateOptionalLayout(descriptor))
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
                val fieldShape = shape.fields[currentDescriptorIndex]
                applyCurrentPropertyContext(
                    ownerDescriptor = descriptor,
                    propertyIndex = currentDescriptorIndex,
                    isTrailing = currentDescriptorIndex >= descriptor.elementsCount - 1,
                    couldBeAbsent = fieldShape.presence is Asn1Presence.OmittedWhenNull,
                    possibleLeadingTags = fieldShape.possibleLeadingTags,
                )
                if (fieldShape.presence is Asn1Presence.Defaulted && !cursor.isAtEnd) {
                    val actualTag = cursor.current().tag
                    val expectedTags = fieldShape.possibleLeadingTags
                    if (expectedTags is Asn1LeadingTagsResolution.Exact && actualTag !in expectedTags.tags) {
                        return decodeElementIndex(descriptor)
                    }
                }
                val couldBeAbsent = fieldShape.presence is Asn1Presence.OmittedWhenNull

                if (cursor.isAtEnd && !couldBeAbsent) {
                    CompositeDecoder.DECODE_DONE
                } else {
                    currentDescriptorIndex
                }
            }

            else -> {
                // list-like descriptors always have elementCount = 1 because
                // they can never know how long the list actually is
                if (cursor.isAtEnd) return CompositeDecoder.DECODE_DONE
                applyCurrentPropertyContext(
                    ownerDescriptor = descriptor,
                    propertyIndex = cursor.position,
                    isTrailing = true,
                    safePropertyNameLookup = true,
                )
                cursor.position
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
        val propertyContext = currentSlot.property
        val propertyDescriptor = propertyContext?.propertyDescriptor
            ?: currentSlot.descriptor
            ?: throw SerializationException("No descriptor available while decoding a primitive value")

        return cursor.consume { processedElement ->
            val effectiveDescriptor =
                if (propertyDescriptor.isInline && propertyDescriptor.elementsCount == 1) {
                    propertyDescriptor.unwrapInlineDescriptorForAsn1()
                } else {
                    propertyDescriptor
                }

            val expectedTag = tagSite(
                inlineHints = DerInlineHints(inlineAnnotation, false),
                property = propertyContext,
                typeDescriptor = propertyDescriptor,
            )?.resolveAgainst(processedElement.tag)

            DerValueCodec.decodePrimitive(
                element = processedElement,
                effectiveDescriptor = effectiveDescriptor,
                declaredDescriptor = propertyDescriptor,
                expectedTag = expectedTag,
            )
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
        if (slot.couldBeAbsent && isCurrentNullableValueAbsent(deserializer, slot)) {
            return nullDecoded()
        }
        return decodeSerializableValue(deserializer)
    }

    /*single call site; code is more legible like that and inline saves a stack frame*/
    private inline fun <T> isCurrentNullableValueAbsent(
        deserializer: DeserializationStrategy<T>,
        slot: DerDecodeSlot,
    ): Boolean {
        if (cursor.isAtEnd) return true

        val property = slot.property
        val descriptor = property?.propertyDescriptor ?: slot.descriptor ?: deserializer.descriptor
        val inlineHints = inlineHintState.peek()
        val openSerializer = resolveOpenPolymorphicAsn1SerializerOrNull(deserializer, serializersModule)
        val tagDispatched = openSerializer is Asn1TagDiscriminatedOpenPolymorphicSerializer<*>
        val expectedLeadingTags = if (openSerializer == null && inlineHints.tag == null && !inlineHints.asBitString) {
            slot.possibleLeadingTags
        } else {
            analysis.possibleLeadingTags(
                descriptor = openSerializer?.descriptor ?: descriptor,
                propertyAsn1Tag = property?.propertyAsn1Tag?.takeUnless { tagDispatched },
                inlineAsn1Tag = inlineHints.tag,
                propertyAsBitString = property?.propertyAsBitString == true,
                inlineAsBitString = inlineHints.asBitString,
            )
        }
        return when (expectedLeadingTags) {
            is Asn1LeadingTagsResolution.Exact -> cursor.current().tag !in expectedLeadingTags.tags
            Asn1LeadingTagsResolution.UnknownInfer -> {
                if (!slot.isTrailing) {
                    throw SerializationException(
                        undecidableAsn1NullableDecodingMessage(
                            ownerSerialName = property?.ownerSerialName ?: descriptor.serialName,
                            propertyName = property?.propertyName ?: descriptor.serialName,
                            propertyIndex = property?.index ?: 0,
                            reason = expectedLeadingTags.reason(),
                        )
                    )
                }
                false
            }
        }
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
        if (tryConsumeEncodedNull(deserializer)) return nullDecoded()

        val propertyContext = currentSlot.property
        if (deserializer.descriptor.isInline) {
            // Let the framework do its inline-class magic **before consuming pending inline hints.**
            return deserializer.deserialize(this)
        }
        val currentAnnotatedElement = cursor.current()
        val inlineHints = inlineHintState.consume()
        val valueSite = analysis.prepareValue(
            descriptor = deserializer.descriptor,
            nullAnalysisDescriptor = propertyContext?.propertyDescriptor ?: deserializer.descriptor,
            inlineHints = inlineHints,
            propertyContext = propertyContext,
            inheritedPropertyTag = polymorphicHandoff.inheritedPropertyTag,
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

    /*single call site; code is more legible like that and inline saves a stack frame*/
    private inline fun tryConsumeEncodedNull(deserializer: DeserializationStrategy<*>): Boolean {
        val element = cursor.currentOrNull() ?: return false
        val property = currentSlot.property
        val descriptor = property?.propertyDescriptor ?: currentSlot.descriptor ?: deserializer.descriptor
        val inlineHints = inlineHintState.peek()
        val propertyTag = polymorphicHandoff.inheritedPropertyTag ?: property?.propertyAsn1Tag
        val effectiveNullEncoding = analysis.analyzeNullable(
            descriptor = descriptor,
            propertyAsn1Tag = propertyTag,
            inlineAsn1Tag = inlineHints.tag,
            propertyAsBitString = property?.propertyAsBitString == true,
            inlineAsBitString = inlineHints.asBitString,
        )

        if (element.isAsn1NullElement()) {
            val descriptorEncodesNull = analysis.analyzeNullable(deserializer.descriptor).encodeNullEnabled
            val encodedNull = effectiveNullEncoding.matchesEncodedNull(element) || descriptorEncodesNull
            if (!encodedNull) {
                if (deserializer.descriptor.serialName.removeSuffix("?") == ASN1_DESCRIPTOR_ELEMENT_TREE) {
                    return false
                }
                throw SerializationException("Null value found, but target value should not have been present!")
            }
        } else {
            if (!effectiveNullEncoding.matchesEncodedNull(element)) return false
        }

        inlineHintState.clear()
        cursor.advance()
        return true
    }

    /*single call site; code is more legible like that and inline saves a stack frame*/
    private inline fun <T> decodeConcreteValue(
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
        val expectedTag = valueSite.tagTemplate?.resolveAgainst(processedElement.tag)
        when (deserializer.descriptor.serialName.removeSuffix("?")) {
            ASN1_DESCRIPTOR_ELEMENT_TREE -> {
                depthGuard.ensureElementTreeFits(
                    processedElement, der.configuration.maxNestingDepth, deserializer.descriptor.serialName
                )
                cursor.advance()
                return castDecoded(DerValueCodec.decodeRawElement(deserializer, processedElement, expectedTag))
            }
        }

        if (deserializer is Asn1Serializable<*, *>) {
            depthGuard.ensureElementTreeFits(
                processedElement, der.configuration.maxNestingDepth, deserializer.descriptor.serialName
            )
            cursor.advance()
            return castDecoded(DerValueCodec.decodeAsn1Serializable(deserializer, processedElement, expectedTag))
        }

        if (deserializer.descriptor.isKotlinTimeInstantDescriptor()) {
            val primitive = processedElement as? Asn1Primitive
                ?: throw SerializationException(
                    "Expected ASN.1 primitive for kotlin.time.Instant, but got ${processedElement::class.simpleName}"
                )
            cursor.advance()
            return castDecoded(DerValueCodec.decodeInstant(primitive, expectedTag))
        }

        // Tag-check for explicitly / implicitly tagged primitives
        val tagToValidate = expectedTag ?: if (!polymorphicHandoff.acceptWireTag) {
            expectedUniversalTag(deserializer.descriptor, valueSite.byteArrayShape)
        } else null

        tagToValidate?.let { expected ->
            if (processedElement.tag != expected) {
                throw SerializationException(Asn1TagMismatchException(expected, processedElement.tag))
            }
        }
        if (deserializer == ByteArraySerializer()) {
            cursor.advance()
            return castDecoded(
                ByteArrayShapePolicy.decodeByteArray(
                    primitive = processedElement.asPrimitive(),
                    shape = valueSite.byteArrayShape,
                    tagToValidate = tagToValidate,
                )
            )
        }

        if (deserializer.descriptor.kind == SerialKind.ENUM) {
            cursor.advance()
            return DerValueCodec.decodeEnum(deserializer, processedElement.asPrimitive(), expectedTag, serializersModule)
        }

        // (3) Primitive kinds → let deserializer consume primitive decoder APIs.
        // This preserves custom primitive-wrapper serializers (e.g. value classes / wrappers
        // with PrimitiveSerialDescriptor) instead of short-circuiting to raw primitive values.
        if (deserializer.descriptor.kind is PrimitiveKind) {
            currentSlot = currentSlot.copy(descriptor = deserializer.descriptor)
            return deserializer.deserialize(this)
        }


        cursor.advance()
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
        return value
    }

    /*single call site; code is more legible like that and inline saves a stack frame*/
    private inline fun initializeStandalonePropertyState(descriptor: SerialDescriptor) {
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

    /*single call site; code is more legible like that and inline saves a stack frame*/
    private inline fun applyCurrentPropertyContext(
        ownerDescriptor: SerialDescriptor,
        propertyIndex: Int,
        isTrailing: Boolean,
        couldBeAbsent: Boolean = false,
        possibleLeadingTags: Asn1LeadingTagsResolution = Asn1LeadingTagsResolution.UnknownInfer,
        safePropertyNameLookup: Boolean = false,
    ) {
        val context = try {
            (ownerDescriptor to propertyIndex).toDerPropertyContext(
                safePropertyNameLookup = safePropertyNameLookup
            )
        } catch (t: IndexOutOfBoundsException) {
            throw SerializationException(t.toString())
        }
        currentSlot = DerDecodeSlot.forProperty(
            context = context,
            isTrailing = isTrailing,
            couldBeAbsent = couldBeAbsent,
            possibleLeadingTags = possibleLeadingTags,
        )
    }

    @OptIn(InternalSerializationApi::class)
    @Suppress("UNCHECKED_CAST")
    /**
     * Decodes sealed-polymorphic CHOICE values by tag-based arm selection.
     *
     * @throws SerializationException if CHOICE descriptors/arms cannot be resolved or matched
     */
    @Throws(SerializationException::class)
    /*single call site; code is more legible like that and inline saves a stack frame*/
    private inline fun <T> decodeChoiceSerializableValue(
        deserializer: SealedClassSerializer<*>,
        currentAnnotatedElement: Asn1Element,
        inlineAnnotation: Asn1Tag?,
    ): T {
        val sealedSerializer = deserializer as SealedClassSerializer<Any>

        rejectAsn1TagOnChoice(
            choiceSerialName = deserializer.descriptor.serialName,
            inlineAsn1Tag = inlineAnnotation,
            propertyAsn1Tag = currentSlot.property?.propertyAsn1Tag,
            classAsn1Tag = deserializer.descriptor.asn1Tag,
        )
        val alternativesDescriptor = deserializer.descriptor.findLikelySealedAlternativesDescriptor()
            ?: throw SerializationException(
                "Could not inspect sealed CHOICE alternatives for ${deserializer.descriptor.serialName}"
            )
        val dispatch = analysis.choiceDispatch(deserializer.descriptor) {
            buildSealedChoiceDispatch<Any>(
                ownerSerialName = deserializer.descriptor.serialName,
                alternativesDescriptor = alternativesDescriptor,
                resolveSerializerByName = { serialName ->
                    sealedSerializer.findPolymorphicSerializerOrNull(this, serialName) as? KSerializer<out Any>
                },
            )
        }
        val selected = dispatch.serializerForDecodeOrNull(currentAnnotatedElement.tag)
            ?: throw SerializationException(
                "No CHOICE alternative of ${deserializer.descriptor.serialName} matches tag ${currentAnnotatedElement.tag}"
            )

        return decodeCurrentElementWith(selected as DeserializationStrategy<T>)
    }

}
