// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(at.asitplus.awesn1.InternalAwesn1Api::class)

package at.asitplus.awesn1.serialization.internal

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.ASN1_DESCRIPTOR_ELEMENT_TREE
import at.asitplus.awesn1.TagClass
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.awesn1.serialization.asn1Tag
import at.asitplus.awesn1.serialization.isAsn1ExplicitWrapperDescriptor
import at.asitplus.awesn1.serialization.resolveAsn1TagTemplate
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.StructureKind

internal data class DerValueSite(
    val descriptor: SerialDescriptor,
    val nullAnalysisDescriptor: SerialDescriptor,
    val inlineHints: DerInlineHints,
    val propertyContext: DerPropertyContext?,
    val effectivePropertyTag: Asn1Tag?,
    val tagTemplate: Asn1Element.Tag.Template?,
    val byteArrayShape: ByteArrayShape,
    val nullEncoding: Asn1NullEncodingAnalysis,
) {
    val ownerSerialName: String
        get() = propertyContext?.ownerSerialName ?: descriptor.serialName

    private val location: String
        get() = propertyContext?.takeIf { it.propertyName != null }?.let {
            "property '${it.propertyName}' (index ${it.index}) in ${it.ownerSerialName}"
        } ?: ownerSerialName

    fun validateSerializerAnnotations(
        allowTaggedRawElementDescriptor: Boolean,
        isGenericAsn1StringSerializer: Boolean,
    ) {
        if (!allowTaggedRawElementDescriptor &&
            descriptor.serialName.removeSuffix("?") == ASN1_DESCRIPTOR_ELEMENT_TREE &&
            tagTemplate != null
        ) {
            throw SerializationException(
                "Raw Asn1Element must not use @Asn1Tag at $location. " +
                        "Remove the tag override or use a strongly typed value/wrapper instead. " +
                        "Resolved tag override was $tagTemplate."
            )
        }
        if (isGenericAsn1StringSerializer && tagTemplate != null) {
            throw SerializationException(
                "Generic ${descriptor.serialName} must not use @Asn1Tag at $location. " +
                        "Use a concrete Asn1String subtype or wrap the tagged value in a dedicated value class instead. " +
                        "Resolved tag override was $tagTemplate."
            )
        }
        requireExplicitWrapperTag()
    }

    private fun requireExplicitWrapperTag() {
        if (!descriptor.isAsn1ExplicitWrapperDescriptor()) return
        if (tagTemplate == null) {
            throw SerializationException(
                "ExplicitlyTagged requires an implicit tag override at $location. " +
                        "Provide @Asn1Tag(tagNumber=..., tagClass=CONTEXT_SPECIFIC, constructed=CONSTRUCTED)."
            )
        }
        val effectiveClass = tagTemplate.tagClass ?: TagClass.UNIVERSAL
        val effectiveConstructed = tagTemplate.constructed ?: true
        if (effectiveClass != TagClass.CONTEXT_SPECIFIC || !effectiveConstructed) {
            throw SerializationException(
                "ExplicitlyTagged requires CONTEXT_SPECIFIC + CONSTRUCTED tag at $location, " +
                        "but effective override is class=$effectiveClass, constructed=$effectiveConstructed."
            )
        }
    }

    fun requireUnambiguousNull() {
        if (nullEncoding.isAmbiguous) {
            throw SerializationException(ambiguousNullEncodingMessage())
        }
    }

    fun ambiguousNullEncodingMessage(): String = ambiguousAsn1NullEncodingMessage(
        ownerSerialName = ownerSerialName,
        propertyName = propertyContext?.propertyName,
        propertyIndex = propertyContext?.index,
    )
}

/** Format-aware descriptor analysis shared by one DER encode/decode operation. */
internal class DerAnalysisContext(
    private val explicitNulls: Boolean,
) {
    private val validatedOptionalLayouts = mutableSetOf<IdentityKey<SerialDescriptor>>()

    /** Validates the static descriptor graph eagerly, including recursive graphs. */
    fun validateDescriptorTree(descriptor: SerialDescriptor) {
        validateDescriptorTree(descriptor, mutableSetOf())
    }

    private fun validateDescriptorTree(
        descriptor: SerialDescriptor,
        visited: MutableSet<IdentityKey<SerialDescriptor>>,
    ) {
        if (!visited.add(IdentityKey(descriptor))) return
        validateOptionalLayout(descriptor)
        for (index in 0 until descriptor.elementsCount) {
            validateDescriptorTree(descriptor.getElementDescriptor(index), visited)
        }
    }

    /** Validates runtime-resolved structures once per operation. */
    @Throws(SerializationException::class)
    fun validateOptionalLayout(descriptor: SerialDescriptor) {
        if (descriptor.kind !is StructureKind.CLASS && descriptor.kind !is StructureKind.OBJECT) return
        if (!validatedOptionalLayouts.add(IdentityKey(descriptor))) return
        descriptor.ensureNoAsn1AmbiguousOptionalLayout(formatExplicitNulls = explicitNulls)
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
