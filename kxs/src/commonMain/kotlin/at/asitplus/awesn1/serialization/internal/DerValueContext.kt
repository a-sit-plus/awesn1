// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(at.asitplus.awesn1.InternalAwesn1Api::class)

package at.asitplus.awesn1.serialization.internal

import at.asitplus.awesn1.ASN1_DESCRIPTOR_ELEMENT_TREE
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.TagClass
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.awesn1.serialization.asn1Tag
import at.asitplus.awesn1.serialization.isAsn1BitString
import at.asitplus.awesn1.serialization.isAsn1ExplicitWrapperDescriptor
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.SerialDescriptor

/** Inline annotation hints awaiting the value reached through an inline serializer. */
internal data class DerInlineHints(
    val tag: Asn1Tag?,
    val asBitString: Boolean,
)

/** Property metadata needed while encoding or decoding one value. */
internal data class DerPropertyContext(
    val ownerDescriptor: SerialDescriptor,
    val index: Int,
    val propertyDescriptor: SerialDescriptor,
    val propertyAsn1Tag: Asn1Tag?,
    val propertyAsBitString: Boolean,
    val propertyName: String?,
) {
    val ownerSerialName: String
        get() = ownerDescriptor.serialName
}

/** Mutable pending-inline state with explicit peek/consume semantics. */
internal class DerInlineHintState {
    private var inlineAsn1Tag: Asn1Tag? = null
    private var inlineAsBitString: Boolean = false

    fun captureInlineHintsFrom(descriptor: SerialDescriptor) {
        descriptor.requireNoAsn1TagOnInlineBackingProperty()
        inlineAsn1Tag = inlineAsn1Tag ?: descriptor.annotations.asn1Tag
        inlineAsBitString = inlineAsBitString || descriptor.isAsn1BitString
    }

    fun peek(): DerInlineHints = DerInlineHints(
        tag = inlineAsn1Tag,
        asBitString = inlineAsBitString,
    )

    fun consume(): DerInlineHints = peek().also { clear() }

    fun clear() {
        inlineAsn1Tag = null
        inlineAsBitString = false
    }
}

/** Resolves the current property metadata from an owning descriptor and property index. */
@Throws(IndexOutOfBoundsException::class)
internal fun Pair<SerialDescriptor, Int>.toDerPropertyContext(
    safePropertyNameLookup: Boolean = false,
): DerPropertyContext {
    val (ownerDescriptor, index) = this
    val propertyName = if (safePropertyNameLookup) {
        runCatching { ownerDescriptor.getElementName(index) }.getOrNull()
    } else {
        ownerDescriptor.getElementName(index)
    }
    return DerPropertyContext(
        ownerDescriptor = ownerDescriptor,
        index = index,
        propertyDescriptor = ownerDescriptor.getElementDescriptor(index),
        propertyAsn1Tag = ownerDescriptor.asn1Tag(index),
        propertyAsBitString = ownerDescriptor.isAsn1BitString(index),
        propertyName = propertyName,
    )
}

/** Immutable, analyzed context for one serializable value. */
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
