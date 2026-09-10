// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(at.asitplus.awesn1.InternalAwesn1Api::class)

package at.asitplus.awesn1.serialization.internal

import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.awesn1.serialization.asn1Tag
import at.asitplus.awesn1.serialization.resolveAsn1TagTemplate
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.StructureKind

/** Format-aware descriptor analysis shared by one DER encode/decode operation. */
internal class DerAnalysisContext(
    internal val explicitNulls: Boolean,
) {
    private val validatedOptionalLayouts = mutableMapOf<IdentityKey<SerialDescriptor>, Asn1StructureShape>()

    /** Validates the static descriptor graph eagerly, including recursive graphs. */
    fun validateDescriptorTree(descriptor: SerialDescriptor) {
        validateDescriptorTree(descriptor, mutableSetOf())
    }

    private fun validateDescriptorTree(
        descriptor: SerialDescriptor,
        visited: MutableSet<IdentityKey<SerialDescriptor>>,
    ) {
        if (!visited.add(IdentityKey(descriptor))) return
        validateOptionalLayout(descriptor)?.let { }
        for (index in 0 until descriptor.elementsCount) {
            validateDescriptorTree(descriptor.getElementDescriptor(index), visited)
        }
    }

    /** Validates runtime-resolved structures once per operation. */
    @Throws(SerializationException::class)
    fun validateOptionalLayout(descriptor: SerialDescriptor): Asn1StructureShape? {
        if (descriptor.kind !is StructureKind.CLASS && descriptor.kind !is StructureKind.OBJECT) return null
        return validatedOptionalLayouts.getOrPut(IdentityKey(descriptor)) {
            descriptor.ensureNoAsn1AmbiguousOptionalLayout(formatExplicitNulls = explicitNulls)
        }
    }

    fun <T : Any> choiceDispatch(
        descriptor: SerialDescriptor,
        build: () -> Asn1TagDiscriminatedDispatch<T>,
    ): Asn1TagDiscriminatedDispatch<T> {
        val shape = validatedOptionalLayouts.getOrPut(IdentityKey(descriptor)) {
            Asn1StructureShape(emptyList())
        }
        @Suppress("UNCHECKED_CAST")
        return (shape.choiceDispatch ?: build().also { shape.choiceDispatch = it }) as Asn1TagDiscriminatedDispatch<T>
    }

    fun analyzeNullable(
        descriptor: SerialDescriptor,
        propertyAsn1Tag: Asn1Tag? = null,
        inlineAsn1Tag: Asn1Tag? = null,
        propertyAsBitString: Boolean = false,
        inlineAsBitString: Boolean = false,
    ): Asn1NullEncodingAnalysis = descriptor.analyzeAsn1NullableNullEncoding(
        propertyAsn1Tag = propertyAsn1Tag,
        inlineAsn1Tag = inlineAsn1Tag,
        propertyAsBitString = propertyAsBitString,
        inlineAsBitString = inlineAsBitString,
        formatExplicitNulls = explicitNulls,
    )

    fun possibleLeadingTags(
        descriptor: SerialDescriptor,
        propertyAsn1Tag: Asn1Tag? = null,
        inlineAsn1Tag: Asn1Tag? = null,
        propertyAsBitString: Boolean = false,
        inlineAsBitString: Boolean = false,
    ): Asn1LeadingTagsResolution = descriptor.possibleLeadingTagsForAsn1(
        propertyAsn1Tag = propertyAsn1Tag,
        inlineAsn1Tag = inlineAsn1Tag,
        propertyAsBitString = propertyAsBitString,
        inlineAsBitString = inlineAsBitString,
    )

    fun prepareValue(
        descriptor: SerialDescriptor,
        nullAnalysisDescriptor: SerialDescriptor,
        inlineHints: DerInlineHints,
        propertyContext: DerPropertyContext?,
        propertyAsn1Tag: Asn1Tag?,
        propertyAsBitString: Boolean,
        includeDescriptorAsBitString: Boolean = false,
    ): DerValueSite = DerValueSite(
        descriptor = descriptor,
        nullAnalysisDescriptor = nullAnalysisDescriptor,
        inlineHints = inlineHints,
        propertyContext = propertyContext,
        effectivePropertyTag = propertyAsn1Tag,
        tagTemplate = resolveAsn1TagTemplate(
            inlineAsn1Tag = inlineHints.tag,
            propertyAsn1Tag = propertyAsn1Tag,
            classAsn1Tag = descriptor.asn1Tag,
        ),
        byteArrayShape = ByteArrayShapePolicy.resolveSerializerShape(
            descriptor = descriptor,
            inlineAsBitString = inlineHints.asBitString,
            propertyAsBitString = propertyAsBitString,
            includeDescriptorAsBitString = includeDescriptorAsBitString,
        ),
        nullEncoding = analyzeNullable(
            descriptor = nullAnalysisDescriptor,
            propertyAsn1Tag = propertyAsn1Tag,
            inlineAsn1Tag = inlineHints.tag,
            propertyAsBitString = propertyAsBitString,
            inlineAsBitString = inlineHints.asBitString,
        ),
    )

    private class IdentityKey<T : Any>(private val value: T) {
        override fun equals(other: Any?): Boolean = other is IdentityKey<*> && value === other.value
        override fun hashCode(): Int = value.hashCode()
    }
}
