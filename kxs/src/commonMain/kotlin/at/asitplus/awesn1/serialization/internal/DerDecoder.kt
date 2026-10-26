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
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.AbstractDecoder
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.internal.AbstractPolymorphicSerializer

/*internal for inlining*/
internal data class DerDecodeSlot(
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
internal class DerElementCursor(private val input: DerInput) {
    var position: Int = 0
        private set
    var consumedStructureElements: Int = 0
        private set

    val isAtEnd: Boolean get() = !input.hasNext()

    fun currentOrNull(): DerValue? = input.peek()

    fun current(): DerValue = currentOrNull()
        ?: throw SerializationException("No ASN.1 element at index $position")

    fun advance(structureElements: Int? = null) {
        input.advance()
        position++
        if (structureElements != null) consumedStructureElements = structureElements
    }

    inline fun <T> consume(decode: (DerValue) -> T): T {
        val decoded = decode(current())
        advance()
        return decoded
    }

    fun finish() = input.finish()
}

internal data class DerDecodeHandoff(
    val inheritedPropertyTag: Asn1Tag? = null,
    val acceptWireTag: Boolean = false,
    val dropOidFromNextStructure: Boolean = false,
) {
    /*single call site; code is more legible like that and inline saves a stack frame*/
    inline fun <T : Any> withSelection(selection: DerDecodeSelection<T>) = copy(
        acceptWireTag = selection.acceptWireTag,
        dropOidFromNextStructure = selection.dropOidFromNextStructure,
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
    input: DerInput,
    override val der: Der,
    private val analysis: DerAnalysisContext = DerAnalysisContext(der.configuration.explicitNulls),
    // Shared across the whole decode so structural recursion is bounded. kotlinx.serialization's decode contract is
    // recursive descent (deserialize -> decodeSerializableElement -> deserialize -> ...), which the iterative raw
    // parser cannot flatten; this counter turns an unrecoverable StackOverflowError on a deeply nested recursive
    // type into a clean SerializationException. Every child decoder MUST receive this same instance.
    private val depthGuard: DerDepthGuard = DerDepthGuard(),
    //internal only for inlining; should actually be private
    internal val polymorphicHandoff: DerDecodeHandoff = DerDecodeHandoff(),
    private val structureOwner: DerDecoder? = null,
) : AbstractDecoder(), at.asitplus.awesn1.serialization.DerDecoder {

    override val serializersModule get() = der.serializersModule

    private val cursor = DerElementCursor(input)
    private var allowPrimitiveContent = false

    internal fun finish() = cursor.finish()
    private var descriptorIndex = 0
    private var currentSlot = DerDecodeSlot()
    private val inlineHintState = DerInlineHintState()


    /*single call site; code is more legible like that and inline saves a stack frame*/
    internal inline fun peekCurrentElementTagOrNull(): Asn1Element.Tag? = cursor.currentOrNull()?.tag
    /*single call site; code is more legible like that and inline saves a stack frame*/
    internal fun peekCurrentElementOrNull(): Asn1Element? = cursor.currentOrNull()?.readTree(
        depthGuard.remainingDepth(der.configuration.maxNestingDepth)
    )

    internal fun peekFirstPrimitive(expectedTag: Asn1Element.Tag): Asn1Primitive? =
        cursor.currentOrNull()?.takeIf { !it.isPrimitive }?.peekFirstPrimitive(expectedTag)

    @Suppress("UNCHECKED_CAST")
    private fun <T> castDecoded(value: Any?): T = value as T

    @Suppress("UNCHECKED_CAST")
    private fun <T> nullDecoded(): T = null as T

    /*two call site; code is more legible like that and inline saves a stack frame*/
    internal fun <T> decodeCurrentElementWith(
        deserializer: DeserializationStrategy<T>,
        handoff: DerDecodeHandoff,
    ): T = cursor.consume { current ->
        val isolated = DerDecoder(
            input = DerInput(listOf(current).iterator()),
            der = der,
            analysis = analysis,
            depthGuard = depthGuard,
            polymorphicHandoff = handoff,
        )
        isolated.currentSlot = DerDecodeSlot.standalone(deserializer.descriptor)
        val decoded = isolated.decodeSerializableValue(deserializer)
        isolated.finish()
        decoded
    }

    @OptIn(ExperimentalSerializationApi::class)
    override fun decodeInline(descriptor: SerialDescriptor): Decoder {
        currentSlot = currentSlot.copy(descriptor = descriptor)
        inlineHintState.captureInlineHintsFrom(descriptor)
        return this
    }

    /**
     * Begins structure decoding with a bounded child input owned by the current value.
     *
     * @throws SerializationException if a structure descriptor is mapped to a non-structure ASN.1 element
     */
    override fun beginStructure(descriptor: SerialDescriptor): CompositeDecoder {

        // Bound structural recursion before descending another level (see [DerDepthGuard]). Balanced by the
        // matching endStructure() decrement.
        depthGuard.enter(der.configuration.maxNestingDepth, descriptor.serialName)

        val element = cursor.current()
        return when (descriptor.kind) {
            is StructureKind.CLASS,
            is StructureKind.OBJECT,
            is StructureKind.LIST,
            is StructureKind.MAP,
            is PolymorphicKind -> {
                val dropOid = polymorphicHandoff.dropOidFromNextStructure
                val cap = when (descriptor.kind) {
                    StructureKind.CLASS, StructureKind.OBJECT -> descriptor.elementsCount + if (dropOid) 1 else 0
                    else -> null
                }
                val children = element.children(
                    maxChildren = cap,
                    allowPrimitiveContent = allowPrimitiveContent ||
                            (element.isPrimitive && (descriptor.isAsn1OctetStringEncapsulatedDescriptor() || element.contentLength == 0L)),
                )
                if (dropOid) {
                    val first = children.peek()?.takeIf { it.isPrimitive && it.tag == Asn1Element.Tag.OID }
                        ?: throw SerializationException("OID discriminator must be the first child")
                    val _ = first.readPrimitive().readOid()
                    children.advance()
                }
                DerDecoder(children, der, analysis, depthGuard, structureOwner = this)
            }
            else -> this
        }
    }

    /** Completes this container before releasing the owning value. Never drains unread input. */
    override fun endStructure(descriptor: SerialDescriptor) {
        cursor.finish()
        structureOwner?.cursor?.advance(structureElements = cursor.position)
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
                                    "but unread element(s) remain"
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

        return cursor.consume { current ->
            val processedElement = current.readPrimitive()
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
        if (cursor.isAtEnd && deserializer.descriptor.isNullable) return nullDecoded()
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
            return decodeChoiceSerializableValue(deserializer, currentAnnotatedElement.tag, valueSite.inlineHints.tag)
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

        if (element.isPrimitive && element.tag == Asn1Element.Tag.NULL && element.contentLength == 0L) {
            val descriptorEncodesNull = analysis.analyzeNullable(deserializer.descriptor).encodeNullEnabled
            val encodedNull = effectiveNullEncoding.matchesEncodedNull(element.tag, element.contentLength, element.isPrimitive) || descriptorEncodesNull
            if (!encodedNull) {
                if (deserializer.descriptor.serialName.removeSuffix("?") == ASN1_DESCRIPTOR_ELEMENT_TREE) {
                    return false
                }
                throw SerializationException("Null value found, but target value should not have been present!")
            }
        } else {
            if (!effectiveNullEncoding.matchesEncodedNull(element.tag, element.contentLength, element.isPrimitive)) return false
        }

        if (element.isPrimitive) element.readPrimitive()
        else element.readTree(depthGuard.remainingDepth(der.configuration.maxNestingDepth))
        inlineHintState.clear()
        cursor.advance()
        return true
    }

    /*single call site; code is more legible like that and inline saves a stack frame*/
    private inline fun <T> decodeConcreteValue(
        deserializer: DeserializationStrategy<T>,
        currentAnnotatedElement: DerValue,
        valueSite: DerValueSite,
    ): T {
        val primitiveDispatch = polymorphicHandoff.acceptWireTag && currentAnnotatedElement.isPrimitive &&
                (deserializer.descriptor.kind is StructureKind.CLASS || deserializer.descriptor.kind is StructureKind.OBJECT)
        // The existing primitive-content dispatch conversion uses a constructed effective tag.
        val effectiveTag = if (primitiveDispatch) Asn1Element.Tag(
            currentAnnotatedElement.tag.tagValue, constructed = true, currentAnnotatedElement.tag.tagClass
        ) else currentAnnotatedElement.tag
        val expectedTag = valueSite.tagTemplate?.resolveAgainst(effectiveTag)
        if (deserializer.descriptor.serialName.removeSuffix("?") == ASN1_DESCRIPTOR_ELEMENT_TREE ||
            deserializer is Asn1Serializable<*, *>
        ) {
            val remainingDepth = depthGuard.remainingDepth(der.configuration.maxNestingDepth)
            val tree = if (primitiveDispatch) {
                if (remainingDepth == 0) throw SerializationException("ASN.1 nesting depth exceeded")
                val content = currentAnnotatedElement.children(allowPrimitiveContent = true)
                val children = mutableListOf<Asn1Element>()
                while (content.hasNext()) {
                    children += content.peek()!!.readTree(remainingDepth - 1)
                    content.advance()
                }
                content.finish()
                Asn1CustomStructure(
                    tag = effectiveTag.tagValue,
                    tagClass = effectiveTag.tagClass,
                    children = children,
                    sortChildren = false,
                    shouldBeSorted = false,
                )
            } else currentAnnotatedElement.readTree(remainingDepth)
            depthGuard.ensureElementTreeFits(tree, der.configuration.maxNestingDepth, deserializer.descriptor.serialName)
            val decoded = if (deserializer is Asn1Serializable<*, *>) {
                DerValueCodec.decodeAsn1Serializable(deserializer, tree, expectedTag)
            } else DerValueCodec.decodeRawElement(deserializer, tree, expectedTag)
            cursor.advance()
            return castDecoded(decoded)
        }

        if (deserializer.descriptor.isKotlinTimeInstantDescriptor()) {
            if (!currentAnnotatedElement.isPrimitive) {
                throw SerializationException("Expected ASN.1 primitive for kotlin.time.Instant, but got ASN.1 structure")
            }
            val primitive = currentAnnotatedElement.readPrimitive()
            cursor.advance()
            return castDecoded(DerValueCodec.decodeInstant(primitive, expectedTag))
        }

        // Tag-check for explicitly / implicitly tagged primitives
        val tagToValidate = expectedTag ?: if (!polymorphicHandoff.acceptWireTag) {
            expectedUniversalTag(deserializer.descriptor, valueSite.byteArrayShape)
        } else null

        tagToValidate?.let { expected ->
            if (effectiveTag != expected) {
                throw SerializationException(Asn1TagMismatchException(expected, effectiveTag))
            }
        }
        if (deserializer == ByteArraySerializer()) {
            val primitive = currentAnnotatedElement.readPrimitive()
            cursor.advance()
            return castDecoded(
                ByteArrayShapePolicy.decodeByteArray(
                    primitive = primitive,
                    shape = valueSite.byteArrayShape,
                    tagToValidate = tagToValidate,
                )
            )
        }

        if (deserializer.descriptor.kind == SerialKind.ENUM) {
            val primitive = currentAnnotatedElement.readPrimitive()
            cursor.advance()
            return DerValueCodec.decodeEnum(deserializer, primitive, expectedTag, serializersModule)
        }

        // (3) Primitive kinds → let deserializer consume primitive decoder APIs.
        // This preserves custom primitive-wrapper serializers (e.g. value classes / wrappers
        // with PrimitiveSerialDescriptor) instead of short-circuiting to raw primitive values.
        if (deserializer.descriptor.kind is PrimitiveKind) {
            currentSlot = currentSlot.copy(descriptor = deserializer.descriptor)
            return deserializer.deserialize(this)
        }


        val childDecoder = DerDecoder(
            input = DerInput(listOf(currentAnnotatedElement).iterator()),
            der = der,
            analysis = analysis,
            depthGuard = depthGuard,
            polymorphicHandoff = DerDecodeHandoff(dropOidFromNextStructure = polymorphicHandoff.dropOidFromNextStructure),
        )
        childDecoder.allowPrimitiveContent = primitiveDispatch
        val value = deserializer.deserialize(childDecoder)
        childDecoder.finish()
        if (deserializer.descriptor.isKotlinSetDescriptor &&
            value is Set<*> &&
            value.size != childDecoder.cursor.consumedStructureElements
        ) {
            throw SerializationException(
                "Duplicate elements cannot be decoded into ${deserializer.descriptor.serialName} without data loss"
            )
        }
        if (deserializer.descriptor.kind is StructureKind.MAP &&
            value is Map<*, *> &&
            value.size * 2 != childDecoder.cursor.consumedStructureElements
        ) {
            throw SerializationException(
                "Duplicate keys cannot be decoded into ${deserializer.descriptor.serialName} without data loss"
            )
        }
        cursor.advance()
        return value
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
        currentTag: Asn1Element.Tag,
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
        val selected = dispatch.serializerForDecodeOrNull(currentTag)
            ?: throw SerializationException(
                "No CHOICE alternative of ${deserializer.descriptor.serialName} matches tag ${currentTag}"
            )

        return decodeCurrentElementWith(selected as DeserializationStrategy<T>, polymorphicHandoff)
    }

}
