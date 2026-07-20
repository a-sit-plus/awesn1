// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(InternalAwesn1Api::class)

package at.asitplus.awesn1.serialization.internal


import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.internal.Source
import at.asitplus.awesn1.encoding.*
import at.asitplus.awesn1.encoding.internal.readFullyToAsn1Elements
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
import kotlinx.serialization.modules.EmptySerializersModule
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
 */
class DerDecoder internal constructor(
    private val elements: List<Asn1Element>,
    override val der: Der,
    private val layoutPlan: DerLayoutPlanContext = DerLayoutPlanContext(der.configuration),
    // Shared across the whole decode so structural recursion is bounded. kotlinx.serialization's decode contract is
    // recursive descent (deserialize -> decodeSerializableElement -> deserialize -> ...), which the iterative raw
    // parser cannot flatten; this counter turns an unrecoverable StackOverflowError on a deeply nested recursive
    // type into a clean SerializationException. Every child decoder MUST receive this same instance.
    private val depthGuard: DerDepthGuard = DerDepthGuard(),
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
    private var dropFirstChildInNextStructure: Boolean = false
    internal fun dropOidFromNextStructure() {
        dropFirstChildInNextStructure = true
    }


    internal fun peekCurrentElementTagOrNull(): Asn1Element.Tag? = elements.getOrNull(elementIndex)?.tag
    internal fun peekCurrentElementOrNull(): Asn1Element? = elements.getOrNull(elementIndex)

    /**
     * Returns the element at [elementIndex] with an explicit bounds check.
     *
     * The decode protocol (decodeElementIndex + the `elementIndex == elements.size` null guard) keeps this index
     * in range, but indexing directly relied on the runtime throwing on overrun — which Kotlin/Wasm does not do as
     * a catchable exception. This surfaces any future invariant breach as a catchable [SerializationException]
     * on every platform instead of a Wasm trap.
     */
    private fun currentElement(): Asn1Element =
        elements.getOrNull(elementIndex)
            ?: throw SerializationException("No ASN.1 element at index $elementIndex (have ${elements.size})")

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
        val current = elements.getOrNull(elementIndex)
            ?: throw SerializationException("No ASN.1 element left while decoding ${deserializer.descriptor.serialName}")
        val isolated = DerDecoder(
            elements = listOf(current),
            der = der,
            layoutPlan = layoutPlan,
            depthGuard = depthGuard,
        )
        isolated.initializeStandalonePropertyState(deserializer.descriptor)
        isolated.currentOwnerSerialName = deserializer.descriptor.serialName
        isolated.currentPropertyName = deserializer.descriptor.serialName
        isolated.currentPropertyIndex = 0
        isolated.dropFirstChildInNextStructure = this.dropFirstChildInNextStructure
        this.dropFirstChildInNextStructure = false
        val decoded = isolated.decodeSerializableValue(deserializer)
        elementIndex++
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
     * Begins structure decoding by materializing a child decoder for structure children.
     *
     * @throws SerializationException if a structure descriptor is mapped to a non-structure ASN.1 element
     */
    override fun beginStructure(descriptor: SerialDescriptor): CompositeDecoder {

        // Bound structural recursion before descending another level (see [DerDepthGuard]). Balanced by the
        // matching endStructure() decrement.
        depthGuard.enter(der.configuration.maxNestingDepth, descriptor.serialName)

        // 1. Pick the element that belongs to *this* level
        val element = currentElement()

        // 2. hand over decoding of the children to a *new* decoder
        elementIndex++

        return when (descriptor.kind) {
            is StructureKind.CLASS,
            is StructureKind.OBJECT,
            is StructureKind.LIST,
            is StructureKind.MAP -> {
                if (element is Asn1Structure || element is Asn1EncapsulatingOctetString) {
                    val children = when(element){
                        is Asn1Structure -> element.children
                        is Asn1EncapsulatingOctetString -> element.children
                        else -> throw ImplementationError("OCTET STRING UNWRAPPING")
                    }

                    val effectiveChildren =
                        if (dropFirstChildInNextStructure) {
                            dropFirstChildInNextStructure = false
                            if (children.isEmpty()) children else children.drop(1)
                        } else children

                    DerDecoder(
                        effectiveChildren,
                        der = der,
                        layoutPlan = layoutPlan,
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
                val effectiveChildren =
                    if (dropFirstChildInNextStructure) {
                        dropFirstChildInNextStructure = false
                        if (children.isEmpty()) children else children.drop(1)
                    } else children

                DerDecoder(
                    effectiveChildren,
                    der = der,
                    layoutPlan = layoutPlan,
                    depthGuard = depthGuard,
                )
            }

            // Primitive wrappers (CHOICE, ENUM, etc.) keep using the same instance
            else -> this

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
                    layoutPlan.ensureNoAmbiguousOptionalLayout(descriptor)
                }
                if (descriptorIndex >= descriptor.elementsCount) {
                    if (elementIndex < elements.size) {
                        throw SerializationException(
                            "Too many ASN.1 elements for ${descriptor.serialName}: " +
                                    "all ${descriptor.elementsCount} properties decoded, " +
                                    "but ${elements.size - elementIndex} element(s) remain"
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

                if (elementIndex >= elements.size && !couldBeNull) {
                    couldBeNull = false
                    CompositeDecoder.DECODE_DONE
                } else {
                    currentDescriptorIndex
                }
            }

            else -> {
                // list-like descriptors always have elementCount = 1 because
                // they can never know how long the list actually is
                val max = if (descriptor.elementsCount > elements.size) descriptor.elementsCount else elements.size
                if (elementIndex >= max) return CompositeDecoder.DECODE_DONE

                if (elementIndex >= elements.size) return CompositeDecoder.DECODE_DONE
                couldBeNull = false

                applyCurrentPropertyContext(
                    ownerDescriptor = descriptor,
                    propertyIndex = elementIndex,
                    isTrailing = true,
                    safePropertyNameLookup = true,
                )
                if (elementIndex < elements.size) elementIndex else CompositeDecoder.DECODE_DONE
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

            PrimitiveKind.BOOLEAN -> processedElement.asPrimitive()
                .decodeToBoolean(expectedTag ?: Asn1Element.Tag.BOOL)

            PrimitiveKind.BYTE -> processedElement.asPrimitive()
                .decodeToInt(expectedTag ?: Asn1Element.Tag.INT)
                .let {
                    if (propertyDescriptor.isKotlinUByteDescriptor()) it.toStrictUByteBacking()
                    else it.toStrictByte()
                }

            PrimitiveKind.CHAR -> processedElement.asPrimitive().decodeString(expectedTag)
                .also { if (it.length != 1) throw SerializationException("String is not a char") }[0]

            PrimitiveKind.DOUBLE -> processedElement.asPrimitive()
                .decodeToDouble(expectedTag ?: Asn1Element.Tag.REAL)

            PrimitiveKind.FLOAT -> processedElement.asPrimitive().decodeToFloat(expectedTag ?: Asn1Element.Tag.REAL)
            PrimitiveKind.INT -> if (propertyDescriptor.isKotlinUIntDescriptor()) {
                processedElement.asPrimitive().decodeToUInt(expectedTag ?: Asn1Element.Tag.INT).toInt()
            } else {
                processedElement.asPrimitive().decodeToInt(expectedTag ?: Asn1Element.Tag.INT)
            }
            PrimitiveKind.LONG -> if (propertyDescriptor.isKotlinULongDescriptor()) {
                processedElement.asPrimitive().decodeToULong(expectedTag ?: Asn1Element.Tag.INT).toLong()
            } else {
                processedElement.asPrimitive().decodeToLong(expectedTag ?: Asn1Element.Tag.INT)
            }
            PrimitiveKind.SHORT -> processedElement.asPrimitive()
                .decodeToInt(expectedTag ?: Asn1Element.Tag.INT)
                .let {
                    if (propertyDescriptor.isKotlinUShortDescriptor()) it.toStrictUShortBacking()
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
        elementIndex++
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
            if (elementIndex == elements.size) {
                return nullDecoded()
            }

            when (val expectedLeadingTags = layoutPlan.possibleLeadingTags(
                descriptor = propertyDescriptor,
                propertyAsn1Tag = propertyAsn1Tag,
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
            elementIndex++
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
        if (elements.isEmpty() && deserializer.descriptor.isNullable) return nullDecoded()
        if (deserializer.descriptor.isInline) {
            // Let the framework do its inline-class magic **before consuming pending inline hints.**
            return deserializer.deserialize(this)
        }
        val currentAnnotatedElement = currentElement()
        val inlineHints = inlineHintState.consume()
        val effectiveTagTemplate = resolveAsn1TagTemplate(
            inlineAsn1Tag = inlineHints.tag,
            propertyAsn1Tag = propertyAsn1Tag,
            classAsn1Tag = deserializer.descriptor.asn1Tag,
        )
        // Asn1OctetString has a concrete wire representation despite sharing the opaque element descriptor.
        if (deserializer != Asn1OctetStringFallbackBase64Serializer) {
            requireNoAsn1TagOnRawElement(
                descriptor = deserializer.descriptor,
                inlineAsn1Tag = inlineHints.tag,
                propertyAsn1Tag = propertyAsn1Tag,
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
            propertyAsn1Tag = propertyAsn1Tag,
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
                propertyAsn1Tag = propertyAsn1Tag,
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
            @Suppress("UNCHECKED_CAST")
            return decodeCurrentElementWith(openSerializer as DeserializationStrategy<T>)
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
            return decodeChoiceSerializableValue(deserializer, currentAnnotatedElement, inlineHints.tag)
        }

        val processedElement = currentAnnotatedElement
        val expectedTag = validateAndResolveImplicitTagOverride(
            actualTag = processedElement.tag,
            inlineAsn1Tag = inlineHints.tag,
            propertyAsn1Tag = propertyAsn1Tag,
            classAsn1Tag = deserializer.descriptor.asn1Tag,
        )
        val hasTagOverride = expectedTag != null

        val isEncodedNull =
            processedElement.isAsn1NullElement() ||
                    (nullEncodingAnalysis.canDecodeNullByZeroLength && processedElement.contentLength == 0) ||
                    (nullEncodingAnalysis.canDecodeNullByConstructedBit && !processedElement.tag.isConstructed)

        if (nullEncodingAnalysis.encodeNullEnabled && isEncodedNull) {
            elementIndex++
            return nullDecoded()
        }

        if (deserializer == Asn1ElementSerializer) {
            expectedTag?.let { ex ->
                if (processedElement.tag != ex) {
                    throw SerializationException(Asn1TagMismatchException(ex, processedElement.tag))
                }
            }
            elementIndex++
            return castDecoded(processedElement)
        }

        when (deserializer.descriptor.serialName.removeSuffix("?")) {
            ASN1_DESCRIPTOR_ELEMENT_TREE -> {
                expectedTag?.let { ex ->
                    if (processedElement.tag != ex) {
                        throw SerializationException(Asn1TagMismatchException(ex, processedElement.tag))
                    }
                }
                elementIndex++
                if (deserializer == Asn1OctetStringFallbackBase64Serializer) {
                    return castDecoded(Asn1OctetString(processedElement.asPrimitive().content))
                }
                require(deserializer is Asn1ElementFallbackBase64SerializerBase<*>) {
                    "Reserved SerialName for Asn1ElementFallbackBase64SerializerBase reused by: ${deserializer::class.simpleName}"}
                return castDecoded(deserializer.decodeFromAsn1Element(processedElement))
            }
        }

        if (deserializer is Asn1Serializable<*, *>) {
            val encodable = decodeAsn1SerializableValue(deserializer, processedElement, expectedTag)
            elementIndex++
            return castDecoded(encodable)
        }

        if (deserializer.descriptor.isKotlinTimeInstantDescriptor()) {
            val primitive = processedElement as? Asn1Primitive
                ?: throw SerializationException(
                    "Expected ASN.1 primitive for kotlin.time.Instant, but got ${processedElement::class.simpleName}"
                )
            val decodedInstant = primitive.decodeInstantWithOptionalImplicitTag(expectedTag)
            elementIndex++
            return castDecoded(decodedInstant)
        }

        // Tag-check for explicitly / implicitly tagged primitives
        val tagToValidate = expectedTag ?: run {
            // If no explicit tag is specified, we should still validate against the default tag
            // for the type being deserialized (when no annotations are present)
            if (!hasTagOverride) {
                ByteArrayShapePolicy.defaultTagForDescriptor(deserializer.descriptor, byteArrayShape)
            } else {
                null
            }
        }

        tagToValidate?.let { expected ->
            if (processedElement.tag != expected) {
                throw SerializationException(Asn1TagMismatchException(expected, processedElement.tag))
            }
        }
        // (2) Fast paths for primitive *unsigned* surrogates & helpers
        when (deserializer) {
            UByte.serializer() -> return processedElement.asPrimitive()
                .decodeToUInt(expectedTag ?: Asn1Element.Tag.INT)
                .toStrictUByte()
                .also { elementIndex++ }.let(::castDecoded)

            UShort.serializer() -> return processedElement.asPrimitive()
                .decodeToUInt(expectedTag ?: Asn1Element.Tag.INT)
                .toStrictUShort()
                .also { elementIndex++ }.let(::castDecoded)

            UInt.serializer() -> return processedElement.asPrimitive()
                .decodeToUInt(expectedTag ?: Asn1Element.Tag.INT)
                .also { elementIndex++ }.let(::castDecoded)

            ULong.serializer() -> return processedElement.asPrimitive()
                .decodeToULong(expectedTag ?: Asn1Element.Tag.INT)
                .also { elementIndex++ }.let(::castDecoded)

            ByteArraySerializer() ->
                return ByteArrayShapePolicy.decodeByteArray(
                    primitive = processedElement.asPrimitive(),
                    shape = byteArrayShape,
                    tagToValidate = tagToValidate,
                ).also { elementIndex++ }.let(::castDecoded)
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
            elementIndex++
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
            elements = mutableListOf(processedElement),
            der = der,
            layoutPlan = layoutPlan,
            depthGuard = depthGuard,
        )
        if (dropFirstChildInNextStructure) {
            childDecoder.dropFirstChildInNextStructure = dropFirstChildInNextStructure
            dropFirstChildInNextStructure = false
        }
        val value = deserializer.deserialize(childDecoder)
        elementIndex++
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
        currentAnnotatedElement: Asn1Element,
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
 * configured `maxNestingDepth`, [enter] throws — converting a would-be `StackOverflowError` into a catchable
 * [SerializationException]. A guard is needed because kotlinx.serialization's encode/decode
 * contract is recursive descent through `serialize`/`deserialize` frames the format cannot flatten or trampoline.
 */
internal class DerDepthGuard(private var depth: Int = 0) {
    fun enter(maxNestingDepth: Int, serialName: String) {
        depth++
        if (depth > maxNestingDepth) {
            throw SerializationException(
                "ASN.1 nesting depth exceeded the configured maxNestingDepth=$maxNestingDepth while " +
                        "processing '$serialName'. This usually means a recursive @Serializable type is being " +
                        "encoded/decoded at extreme depth; raise DerConfiguration.maxNestingDepth only if this " +
                        "nesting is expected."
            )
        }
    }

    fun exit() {
        depth--
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
