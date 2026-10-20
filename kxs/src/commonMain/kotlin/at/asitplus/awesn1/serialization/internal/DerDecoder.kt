// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(InternalAwesn1Api::class)

package at.asitplus.awesn1.serialization.internal


import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.*
import at.asitplus.awesn1.serialization.Asn1ElementSerializer
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.awesn1.serialization.Asn1Serializable
import at.asitplus.awesn1.serialization.Der
import at.asitplus.awesn1.serialization.asn1Tag
import at.asitplus.awesn1.serialization.isAsn1BitString
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
    private val input: DerInput,
    override val der: Der,
    private val layoutPlan: DerLayoutPlanContext = DerLayoutPlanContext(der.configuration),
    // Shared across the whole decode so structural recursion is bounded. kotlinx.serialization's decode contract is
    // recursive descent (deserialize -> decodeSerializableElement -> deserialize -> ...), which the iterative raw
    // parser cannot flatten; this counter turns an unrecoverable StackOverflowError on a deeply nested recursive
    // type into a clean SerializationException. Every child decoder MUST receive this same instance.
    private val depthGuard: DerDepthGuard = DerDepthGuard(),
    private val structureOwner: DerDecoder? = null,
) : AbstractDecoder(), at.asitplus.awesn1.serialization.DerDecoder {

    override val serializersModule get() = der.serializersModule

    private var elementIndex = 0
    private var descriptorIndex = 0
    private lateinit var propertyDescriptor: SerialDescriptor
    private var propertyAsn1Tag: Asn1Tag? = null
    private var propertyAsBitString: Boolean = false
    private val inlineHintState = DerInlineHintState()
    private var couldBeNull = false
    private var currentOwnerSerialName: String? = null
    private var currentPropertyName: String? = null
    private var currentPropertyIndex: Int? = null
    private var currentPropertyIsTrailing = true
    private var dropOidFromNextStructure: ObjectIdentifier? = null
    private var inheritedOpenPolymorphicTag: Asn1Tag? = null
    private var dispatchedTagAccepted = false
    internal fun dropOidFromNextStructure(oid: ObjectIdentifier) {
        dropOidFromNextStructure = oid
    }
    internal fun acceptDispatchedTagForNextValue() {
        dispatchedTagAccepted = true
    }


    internal fun peekCurrentElementTagOrNull(): Asn1Element.Tag? = input.peek()?.tag
    internal fun peekCurrentElementOrNull(): Asn1Element? = input.peek()?.readTree(
        depthGuard.remainingDepth(der.configuration.maxNestingDepth)
    )
    internal fun peekFirstPrimitive(expectedTag: Asn1Element.Tag): Asn1Primitive? =
        input.peek()?.takeIf { it.isStructure }?.peekFirstPrimitive(expectedTag)

    private var allowPrimitiveContent = false
    private var consumedStructureElements = 0

    private fun currentElement(): DerValue = input.peek()
        ?: throw SerializationException("No ASN.1 element at index $elementIndex")

    private fun consumeCurrentValue() {
        input.advance()
        elementIndex++
    }

    internal fun finish() = input.finish()

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
    internal fun <T> decodeCurrentElementWith(deserializer: DeserializationStrategy<T>): T {
        val current = input.peek()
            ?: throw SerializationException("No ASN.1 element left while decoding ${deserializer.descriptor.serialName}")
        val isolated = DerDecoder(
            input = IteratorDerInput(listOf(current).iterator()),
            der = der,
            layoutPlan = layoutPlan,
            depthGuard = depthGuard,
        )
        isolated.initializeStandalonePropertyState(deserializer.descriptor)
        isolated.currentOwnerSerialName = deserializer.descriptor.serialName
        isolated.currentPropertyName = deserializer.descriptor.serialName
        isolated.currentPropertyIndex = 0
        isolated.dropOidFromNextStructure = this.dropOidFromNextStructure
        isolated.inheritedOpenPolymorphicTag = this.inheritedOpenPolymorphicTag
        isolated.dispatchedTagAccepted = this.dispatchedTagAccepted
        this.dispatchedTagAccepted = false
        this.dropOidFromNextStructure = null
        val decoded = isolated.decodeSerializableValue(deserializer)
        isolated.finish()
        consumeCurrentValue()
        return decoded
    }

    @OptIn(ExperimentalSerializationApi::class)
    override fun decodeInline(descriptor: SerialDescriptor): Decoder {
        if (!::propertyDescriptor.isInitialized) {
            initializeStandalonePropertyState(descriptor)
        }
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

        val element = currentElement()
        return when (descriptor.kind) {
            is StructureKind.CLASS, is StructureKind.OBJECT,
            is StructureKind.LIST, is StructureKind.MAP, is PolymorphicKind -> {
                val oid = dropOidFromNextStructure
                dropOidFromNextStructure = null
                val cap = when (descriptor.kind) {
                    StructureKind.CLASS, StructureKind.OBJECT -> descriptor.elementsCount + if (oid != null) 1 else 0
                    else -> null
                }
                val children = element.children(cap, allowPrimitiveContent)
                allowPrimitiveContent = false
                if (oid != null) {
                    val first = children.peek()?.takeIf { it.isPrimitive && it.tag == Asn1Element.Tag.OID }
                    if (first == null || first.readPrimitive().readOid() != oid) {
                        throw SerializationException("OID discriminator $oid must be the first child")
                    }
                    children.advance()
                }
                DerDecoder(children, der, layoutPlan, depthGuard, structureOwner = this)
            }
            else -> this
        }
    }

    override fun endStructure(descriptor: SerialDescriptor) {
        input.finish()
        structureOwner?.let {
            it.consumedStructureElements = elementIndex
            it.consumeCurrentValue()
        }
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
                    layoutPlan.ensureNoAmbiguousOptionalLayout(descriptor)
                }
                if (descriptorIndex >= descriptor.elementsCount) {
                    if (input.hasNext()) {
                        throw SerializationException(
                            "Too many ASN.1 elements for ${descriptor.serialName}: " +
                                    "all ${descriptor.elementsCount} properties decoded, " +
                                    "but unread element(s) remain"
                        )
                    }
                    return CompositeDecoder.DECODE_DONE
                }
                val currentDescriptorIndex = descriptorIndex++
                val propertyContext = applyCurrentPropertyContext(
                    ownerDescriptor = descriptor,
                    propertyIndex = currentDescriptorIndex,
                    isTrailing = currentDescriptorIndex >= descriptor.elementsCount - 1,
                )
                val nullEncodingAnalysis = layoutPlan.analyzeNullable(
                    descriptor = propertyContext.propertyDescriptor,
                    propertyAsn1Tag = propertyContext.propertyAsn1Tag,
                    propertyAsBitString = propertyContext.propertyAsBitString,
                )
                couldBeNull = propertyContext.propertyDescriptor.isNullable && !nullEncodingAnalysis.encodeNullEnabled

                if (!input.hasNext() && !couldBeNull) {
                    couldBeNull = false
                    CompositeDecoder.DECODE_DONE
                } else {
                    currentDescriptorIndex
                }
            }

            else -> {
                // list-like descriptors always have elementCount = 1 because
                // they can never know how long the list actually is
                if (!input.hasNext()) return CompositeDecoder.DECODE_DONE
                couldBeNull = false

                applyCurrentPropertyContext(
                    ownerDescriptor = descriptor,
                    propertyIndex = elementIndex,
                    isTrailing = true,
                    safePropertyNameLookup = true,
                )
                if (input.hasNext()) elementIndex else CompositeDecoder.DECODE_DONE
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

        val currentAnnotatedElement = currentElement()
        val processedElement = currentAnnotatedElement

        val effectiveDescriptor =
            if (propertyDescriptor.isInline && propertyDescriptor.elementsCount == 1) {
                propertyDescriptor.unwrapInlineDescriptorForAsn1()
            } else {
                propertyDescriptor
            }

        val expectedTag = validateAndResolveImplicitTagOverride(
            actualTag = processedElement.tag,
            inlineAsn1Tag = inlineAnnotation,
            propertyAsn1Tag = propertyAsn1Tag,
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

            PrimitiveKind.BOOLEAN -> processedElement.readPrimitive()
                .decodeToBoolean(expectedTag ?: Asn1Element.Tag.BOOL)

            PrimitiveKind.BYTE -> processedElement.readPrimitive()
                .decodeToInt(expectedTag ?: Asn1Element.Tag.INT)
                .let {
                    if (propertyDescriptor.isKotlinUByteDescriptor()) it.toStrictUByteBacking()
                    else it.toStrictByte()
                }

            PrimitiveKind.CHAR -> processedElement.readPrimitive().decodeString(expectedTag)
                .also { if (it.length != 1) throw SerializationException("String is not a char") }[0]

            PrimitiveKind.DOUBLE -> processedElement.readPrimitive()
                .decodeToDouble(expectedTag ?: Asn1Element.Tag.REAL)

            PrimitiveKind.FLOAT -> processedElement.readPrimitive().decodeToFloat(expectedTag ?: Asn1Element.Tag.REAL)
            PrimitiveKind.INT -> if (propertyDescriptor.isKotlinUIntDescriptor()) {
                processedElement.readPrimitive().decodeToUInt(expectedTag ?: Asn1Element.Tag.INT).toInt()
            } else {
                processedElement.readPrimitive().decodeToInt(expectedTag ?: Asn1Element.Tag.INT)
            }
            PrimitiveKind.LONG -> if (propertyDescriptor.isKotlinULongDescriptor()) {
                processedElement.readPrimitive().decodeToULong(expectedTag ?: Asn1Element.Tag.INT).toLong()
            } else {
                processedElement.readPrimitive().decodeToLong(expectedTag ?: Asn1Element.Tag.INT)
            }
            PrimitiveKind.SHORT -> processedElement.readPrimitive()
                .decodeToInt(expectedTag ?: Asn1Element.Tag.INT)
                .let {
                    if (propertyDescriptor.isKotlinUShortDescriptor()) it.toStrictUShortBacking()
                    else it.toStrictShort()
                }

            PrimitiveKind.STRING -> processedElement.readPrimitive().decodeString(expectedTag)
            SerialKind.ENUM -> processedElement.readPrimitive()
                .decodeToEnumOrdinal(expectedTag ?: Asn1Element.Tag.ENUM)

            else -> throw SerializationException(
                "Unsupported descriptor kind ${propertyDescriptor.kind} for ${effectiveDescriptor.serialName} in decodeValue(). " +
                        "Provide a custom serializer or use a supported ASN.1 mapping shape."
            )
        } as Any
        consumeCurrentValue()
        return decoded

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

        val nullableCouldBeAbsent = couldBeNull
        val descriptorNullEncodingAnalysis = layoutPlan.analyzeNullable(deserializer.descriptor)
        if (nullableCouldBeAbsent) {
            val pendingInlineHints = inlineHintState.peek()
            couldBeNull = false
            if (!input.hasNext()) {
                return nullDecoded()
            }

            val openSerializer = resolveOpenPolymorphicAsn1SerializerOrNull(deserializer, serializersModule)
            val tagDispatched = openSerializer is Asn1TagDiscriminatedOpenPolymorphicSerializer<*>
            when (val expectedLeadingTags = layoutPlan.possibleLeadingTags(
                descriptor = openSerializer?.descriptor ?: propertyDescriptor,
                propertyAsn1Tag = propertyAsn1Tag.takeUnless { tagDispatched },
                inlineAsn1Tag = pendingInlineHints.tag,
                propertyAsBitString = propertyAsBitString,
                inlineAsBitString = pendingInlineHints.asBitString,
            )) {
                is Asn1LeadingTagsResolution.Exact -> {
                    val actualTag = currentElement().tag
                    if (actualTag !in expectedLeadingTags.tags) {
                        return nullDecoded()
                    }
                }

                Asn1LeadingTagsResolution.UnknownInfer -> {
                    if (!currentPropertyIsTrailing) {
                        throw SerializationException(
                            undecidableAsn1NullableDecodingMessage(
                                ownerSerialName = currentOwnerSerialName
                                    ?: deserializer.descriptor.serialName,
                                propertyName = currentPropertyName
                                    ?: propertyDescriptor.serialName,
                                propertyIndex = currentPropertyIndex ?: -1,
                                reason = expectedLeadingTags.reason(),
                            )
                        )
                    }
                }
            }
        }
        val currentAnnotatedElement = currentElement()
        if (currentAnnotatedElement.isAsn1NullElement()) {
            val propertyDescriptorEncodesNull = ::propertyDescriptor.isInitialized &&
                    layoutPlan.analyzeNullable(
                        descriptor = propertyDescriptor,
                        propertyAsn1Tag = propertyAsn1Tag,
                        propertyAsBitString = propertyAsBitString,
                    ).encodeNullEnabled
            if (!propertyDescriptorEncodesNull && !descriptorNullEncodingAnalysis.encodeNullEnabled) {
                throw SerializationException("Null value found, but target value should not have been present!")
            }
            currentAnnotatedElement.readPrimitive()
            consumeCurrentValue()
            return nullDecoded()
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
        if (!input.hasNext() && deserializer.descriptor.isNullable) return nullDecoded()
        if (deserializer.descriptor.isInline) {
            // Let the framework do its inline-class magic **before consuming pending inline hints.**
            return deserializer.deserialize(this)
        }
        val currentAnnotatedElement = currentElement()
        val inlineHints = inlineHintState.consume()
        val effectivePropertyAsn1Tag = inheritedOpenPolymorphicTag ?: propertyAsn1Tag
        val effectiveTagTemplate = resolveAsn1TagTemplate(
            inlineAsn1Tag = inlineHints.tag,
            propertyAsn1Tag = effectivePropertyAsn1Tag,
            classAsn1Tag = deserializer.descriptor.asn1Tag,
        )
        // Asn1OctetString has a concrete wire representation despite sharing the opaque element descriptor.
        if (deserializer != Asn1OctetStringFallbackBase64Serializer) {
            requireNoAsn1TagOnRawElement(
                descriptor = deserializer.descriptor,
                inlineAsn1Tag = inlineHints.tag,
                propertyAsn1Tag = effectivePropertyAsn1Tag,
                classAsn1Tag = deserializer.descriptor.asn1Tag,
                ownerSerialName = currentOwnerSerialName ?: deserializer.descriptor.serialName,
                propertyName = currentPropertyName,
                propertyIndex = currentPropertyIndex,
            )
        }
        requireNoAsn1TagOnGenericAsn1String(
            isGenericAsn1StringSerializer = deserializer == Asn1String.Companion,
            descriptor = deserializer.descriptor,
            inlineAsn1Tag = inlineHints.tag,
            propertyAsn1Tag = effectivePropertyAsn1Tag,
            classAsn1Tag = deserializer.descriptor.asn1Tag,
            ownerSerialName = currentOwnerSerialName ?: deserializer.descriptor.serialName,
            propertyName = currentPropertyName,
            propertyIndex = currentPropertyIndex,
        )
        requireAsn1ExplicitWrapperTag(
            descriptor = deserializer.descriptor,
            tagTemplate = effectiveTagTemplate,
            ownerSerialName = currentOwnerSerialName ?: deserializer.descriptor.serialName,
            propertyName = currentPropertyName,
            propertyIndex = currentPropertyIndex,
        )
        val byteArrayShape = ByteArrayShapePolicy.resolveSerializerShape(
            descriptor = deserializer.descriptor,
            layoutPlan = layoutPlan,
            inlineAsBitString = inlineHints.asBitString,
            propertyAsBitString = propertyAsBitString,
        )
        val descriptorNullEncodingAnalysis = layoutPlan.analyzeNullable(
            descriptor = deserializer.descriptor,
            inlineAsn1Tag = inlineHints.tag,
            inlineAsBitString = inlineHints.asBitString,
        )
        val propertyNullEncodingAnalysis = if (::propertyDescriptor.isInitialized) {
            layoutPlan.analyzeNullable(
                descriptor = propertyDescriptor,
                propertyAsn1Tag = effectivePropertyAsn1Tag,
                inlineAsn1Tag = inlineHints.tag,
                propertyAsBitString = propertyAsBitString,
                inlineAsBitString = inlineHints.asBitString,
            )
        } else {
            null
        }
        val nullEncodingAnalysis = propertyNullEncodingAnalysis ?: descriptorNullEncodingAnalysis
        val nullAnalysisOwnerSerialName = if (::propertyDescriptor.isInitialized) {
            propertyDescriptor.serialName
        } else {
            deserializer.descriptor.serialName
        }
        if (nullEncodingAnalysis.isAmbiguous) {
            throw SerializationException(
                ambiguousAsn1NullEncodingMessage(ownerSerialName = nullAnalysisOwnerSerialName)
            )
        }

        resolveOpenPolymorphicAsn1SerializerOrNull(deserializer, serializersModule)?.let { openSerializer ->
            if (openSerializer.descriptor == deserializer.descriptor) {
                throw SerializationException(
                    "Open polymorphism for ${deserializer.descriptor.serialName} resolved to itself. " +
                            "Register a concrete ASN.1 open-polymorphic serializer in DER { serializersModule = ... }."
                )
            }
            val previousInheritedTag = inheritedOpenPolymorphicTag
            //@formatter:off
            inheritedOpenPolymorphicTag = if (openSerializer is Asn1TagDiscriminatedOpenPolymorphicSerializer<*>) null
                                        else previousInheritedTag ?: inlineHints.tag ?: propertyAsn1Tag
            //@formatter:on
            @Suppress("UNCHECKED_CAST")
            return try {
                decodeCurrentElementWith(openSerializer as DeserializationStrategy<T>)
            } finally {
                inheritedOpenPolymorphicTag = previousInheritedTag
            }
        }

        if (deserializer.descriptor.kind is PolymorphicKind.OPEN && deserializer is AbstractPolymorphicSerializer<*>) {
            throw SerializationException(
                "Open polymorphism for ${deserializer.descriptor.serialName} requires an ASN.1 serializer " +
                        "registered in DER { serializersModule = ... } via polymorphicByTag(...) " +
                        "or polymorphicByOid(...)."
            )
        }

        if (isAsn1ChoiceRequested(deserializer.descriptor)
            && deserializer is SealedClassSerializer<*>
        ) {
            return decodeChoiceSerializableValue(deserializer, currentAnnotatedElement.tag, inlineHints.tag)
        }

        val acceptedDispatchedTag = dispatchedTagAccepted.also { dispatchedTagAccepted = false }
        val primitiveDispatch = acceptedDispatchedTag && currentAnnotatedElement.isPrimitive &&
            (deserializer.descriptor.kind is StructureKind.CLASS || deserializer.descriptor.kind is StructureKind.OBJECT)
        val processedElement = currentAnnotatedElement
        val effectiveTag = if (primitiveDispatch) Asn1Element.Tag(
            processedElement.tag.tagValue, constructed = true, tagClass = processedElement.tag.tagClass
        ) else processedElement.tag
        val expectedTag = validateAndResolveImplicitTagOverride(
            actualTag = effectiveTag,
            inlineAsn1Tag = inlineHints.tag,
            propertyAsn1Tag = effectivePropertyAsn1Tag,
            classAsn1Tag = deserializer.descriptor.asn1Tag,
        )
        val hasTagOverride = expectedTag != null

        val isEncodedNull =
            (!primitiveDispatch && processedElement.isAsn1NullElement()) ||
                    (nullEncodingAnalysis.canDecodeNullByZeroLength && processedElement.contentLength == 0L) ||
                    (nullEncodingAnalysis.canDecodeNullByConstructedBit && !effectiveTag.isConstructed)

        if (nullEncodingAnalysis.encodeNullEnabled && isEncodedNull) {
            if (processedElement.isPrimitive) processedElement.readPrimitive()
            else processedElement.readTree(depthGuard.remainingDepth(der.configuration.maxNestingDepth))
            consumeCurrentValue()
            return nullDecoded()
        }

        if (deserializer == Asn1ElementSerializer) {
            val tree = processedElement.readTree(depthGuard.remainingDepth(der.configuration.maxNestingDepth))
            depthGuard.ensureElementTreeFits(tree, der.configuration.maxNestingDepth, deserializer.descriptor.serialName)
            expectedTag?.let { ex ->
                if (processedElement.tag != ex) {
                    throw SerializationException(Asn1TagMismatchException(ex, processedElement.tag))
                }
            }
            consumeCurrentValue()
            return castDecoded(tree)
        }

        when (deserializer.descriptor.serialName.removeSuffix("?")) {
            ASN1_DESCRIPTOR_ELEMENT_TREE -> {
                val tree = processedElement.readTree(depthGuard.remainingDepth(der.configuration.maxNestingDepth))
                depthGuard.ensureElementTreeFits(tree, der.configuration.maxNestingDepth, deserializer.descriptor.serialName)
                expectedTag?.let { ex ->
                    if (processedElement.tag != ex) {
                        throw SerializationException(Asn1TagMismatchException(ex, processedElement.tag))
                    }
                }
                consumeCurrentValue()
                if (deserializer == Asn1OctetStringFallbackBase64Serializer) {
                    return castDecoded(Asn1OctetString(tree.asPrimitive().content))
                }
                require(deserializer is Asn1ElementFallbackBase64SerializerBase<*>) {
                    "Reserved SerialName for Asn1ElementFallbackBase64SerializerBase reused by: ${deserializer::class.simpleName}"}
                return castDecoded(deserializer.decodeFromAsn1Element(tree))
            }
        }

        if (deserializer is Asn1Serializable<*, *>) {
            val remainingDepth = depthGuard.remainingDepth(der.configuration.maxNestingDepth)
            val tree = if (primitiveDispatch) {
                require(remainingDepth > 0) { "ASN.1 nesting depth exceeded while interpreting primitive content" }
                val children = processedElement.children(allowPrimitiveContent = true)
                val materialized = mutableListOf<Asn1Element>()
                while (children.hasNext()) {
                    materialized += checkNotNull(children.peek()).readTree(remainingDepth - 1)
                    children.advance()
                }
                children.finish()
                Asn1CustomStructure(
                    children = materialized, tag = effectiveTag.tagValue, tagClass = effectiveTag.tagClass,
                    sortChildren = false, shouldBeSorted = false,
                )
            } else processedElement.readTree(remainingDepth)
            depthGuard.ensureElementTreeFits(tree, der.configuration.maxNestingDepth, deserializer.descriptor.serialName)
            val encodable = decodeAsn1SerializableValue(deserializer, tree, expectedTag)
            consumeCurrentValue()
            return castDecoded(encodable)
        }

        if (deserializer.descriptor.isKotlinTimeInstantDescriptor()) {
            val primitive = processedElement.readPrimitive()
            val decodedInstant = primitive.decodeInstantWithOptionalImplicitTag(expectedTag)
            consumeCurrentValue()
            return castDecoded(decodedInstant)
        }

        // Tag-check for explicitly / implicitly tagged primitives
        val tagToValidate = expectedTag ?: run {
            // If no explicit tag is specified, we should still validate against the default tag
            // for the type being deserialized (when no annotations are present)
            if (!hasTagOverride && !acceptedDispatchedTag) {
                ByteArrayShapePolicy.defaultTagForDescriptor(deserializer.descriptor, byteArrayShape)
            } else {
                null
            }
        }

        tagToValidate?.let { expected ->
            if (effectiveTag != expected) {
                throw SerializationException(Asn1TagMismatchException(expected, effectiveTag))
            }
        }
        // (2) Fast paths for primitive *unsigned* surrogates & helpers
        when (deserializer) {
            UByte.serializer() -> return processedElement.readPrimitive()
                .decodeToUInt(expectedTag ?: Asn1Element.Tag.INT)
                .toStrictUByte()
                .also { consumeCurrentValue() }.let(::castDecoded)

            UShort.serializer() -> return processedElement.readPrimitive()
                .decodeToUInt(expectedTag ?: Asn1Element.Tag.INT)
                .toStrictUShort()
                .also { consumeCurrentValue() }.let(::castDecoded)

            UInt.serializer() -> return processedElement.readPrimitive()
                .decodeToUInt(expectedTag ?: Asn1Element.Tag.INT)
                .also { consumeCurrentValue() }.let(::castDecoded)

            ULong.serializer() -> return processedElement.readPrimitive()
                .decodeToULong(expectedTag ?: Asn1Element.Tag.INT)
                .also { consumeCurrentValue() }.let(::castDecoded)

            ByteArraySerializer() ->
                return ByteArrayShapePolicy.decodeByteArray(
                    primitive = processedElement.readPrimitive(),
                    shape = byteArrayShape,
                    tagToValidate = tagToValidate,
                ).also { consumeCurrentValue() }.let(::castDecoded)
        }

        if (deserializer.descriptor.kind == SerialKind.ENUM) {
            val ordinal = processedElement.readPrimitive()
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
            consumeCurrentValue()
            return deserializer.deserialize(enumDecoder)
        }

        // (3) Primitive kinds → let deserializer consume primitive decoder APIs.
        // This preserves custom primitive-wrapper serializers (e.g. value classes / wrappers
        // with PrimitiveSerialDescriptor) instead of short-circuiting to raw primitive values.
        if (deserializer.descriptor.kind is PrimitiveKind) {
            if (!::propertyDescriptor.isInitialized) {
                initializeStandalonePropertyState(deserializer.descriptor)
            }
            if (propertyAsn1Tag == null) {
                propertyAsn1Tag = deserializer.descriptor.annotations.asn1Tag
            }
            return deserializer.deserialize(this)
        }


        val childDecoder = DerDecoder(
            input = IteratorDerInput(listOf(processedElement).iterator()),
            der = der,
            layoutPlan = layoutPlan,
            depthGuard = depthGuard,
        )
        if (dropOidFromNextStructure != null) {
            childDecoder.dropOidFromNextStructure = dropOidFromNextStructure
            dropOidFromNextStructure = null
        }
        childDecoder.allowPrimitiveContent = primitiveDispatch
        val value = deserializer.deserialize(childDecoder)
        childDecoder.finish()
        if (deserializer.descriptor.isKotlinSetDescriptor &&
            value is Set<*> &&
            value.size != childDecoder.consumedStructureElements
        ) {
            throw SerializationException(
                "Duplicate elements cannot be decoded into ${deserializer.descriptor.serialName} without data loss"
            )
        }
        consumeCurrentValue()
        return value
    }

    private fun initializeStandalonePropertyState(descriptor: SerialDescriptor) {
        propertyDescriptor = descriptor
        propertyAsn1Tag = descriptor.annotations.asn1Tag
        propertyAsBitString = descriptor.isAsn1BitString
    }

    private fun applyCurrentPropertyContext(
        ownerDescriptor: SerialDescriptor,
        propertyIndex: Int,
        isTrailing: Boolean,
        safePropertyNameLookup: Boolean = false,
    ): DerPropertyContext {
        val context = try {
            (ownerDescriptor to propertyIndex).toDerPropertyContext(
                safePropertyNameLookup = safePropertyNameLookup
            )
        } catch (t: IndexOutOfBoundsException) {
            throw SerializationException(t.toString())
        }
        propertyDescriptor = context.propertyDescriptor
        propertyAsn1Tag = context.propertyAsn1Tag
        propertyAsBitString = context.propertyAsBitString
        currentOwnerSerialName = context.ownerSerialName
        currentPropertyName = context.propertyName
        currentPropertyIndex = context.index
        currentPropertyIsTrailing = isTrailing
        return context
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
        deserializer: DeserializationStrategy<T>,
        currentTag: Asn1Element.Tag,
        inlineAnnotation: Asn1Tag?,
    ): T {
        if (deserializer.descriptor.kind !is PolymorphicKind.SEALED) {
            throw SerializationException(
                "ASN.1 CHOICE requires a sealed polymorphic descriptor, but got ${deserializer.descriptor.kind}"
            )
        }

        val sealedSerializer = deserializer as? SealedClassSerializer<Any>
            ?: throw SerializationException(
                "ASN.1 CHOICE only supports kotlinx SealedClassSerializer"
            )

        rejectAsn1TagOnChoice(
            choiceSerialName = deserializer.descriptor.serialName,
            inlineAsn1Tag = inlineAnnotation,
            propertyAsn1Tag = propertyAsn1Tag,
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
        val selected = dispatch.serializerForDecodeOrNull(currentTag)
            ?: throw Asn1ChoiceNoMatchingAlternativeException(
                "No CHOICE alternative of ${deserializer.descriptor.serialName} matches tag ${currentTag}"
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
    fun remainingDepth(maxNestingDepth: Int): Int {
        check(depth in 0..maxNestingDepth) { "Invalid ASN.1 typed nesting depth" }
        return maxNestingDepth - depth
    }

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

@Throws(SerializationException::class)
private fun Asn1Primitive.decodeAsn1TimeWithOptionalImplicitTag(expectedTag: Asn1Element.Tag?): Asn1Time =
    when (expectedTag) {
        null -> Asn1Time.decodeFromTlv(this)
        Asn1Element.Tag.TIME_UTC -> Asn1Time(
            instant = decodeInstantWithOptionalImplicitTag(expectedTag),
            formatOverride = Asn1Time.Format.UTC,
        )
        Asn1Element.Tag.TIME_GENERALIZED -> Asn1Time(
            instant = decodeInstantWithOptionalImplicitTag(expectedTag),
            formatOverride = Asn1Time.Format.GENERALIZED,
        )
        else -> Asn1Time(decodeInstantWithOptionalImplicitTag(expectedTag))
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
                -> decodeToString()

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

private fun UInt.toStrictUByte(): UByte =
    if (this <= UByte.MAX_VALUE.toUInt()) toUByte()
    else throw SerializationException("ASN.1 INTEGER value $this is out of range for UByte")

private fun UInt.toStrictUShort(): UShort =
    if (this <= UShort.MAX_VALUE.toUInt()) toUShort()
    else throw SerializationException("ASN.1 INTEGER value $this is out of range for UShort")

private fun Int.toStrictUByteBacking(): Byte =
    if (this in 0..UByte.MAX_VALUE.toInt()) toByte()
    else throw SerializationException("ASN.1 INTEGER value $this is out of range for UByte")

private fun Int.toStrictUShortBacking(): Short =
    if (this in 0..UShort.MAX_VALUE.toInt()) toShort()
    else throw SerializationException("ASN.1 INTEGER value $this is out of range for UShort")
