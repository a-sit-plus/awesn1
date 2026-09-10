// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(
    at.asitplus.awesn1.InternalAwesn1Api::class,
    kotlinx.serialization.SealedSerializationApi::class,
)

package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.Asn1Element
import kotlinx.serialization.descriptors.SerialDescriptor

private class Asn1LeadingTagsAnnotation(
    private val provider: () -> Set<Asn1Element.Tag>
) : Annotation {
    val leadingTags: Set<Asn1Element.Tag>
        get() = provider()
}

internal class Asn1LeadingTagsSerialDescriptor(
    private val delegate: SerialDescriptor,
    private val leadingTagsProvider: () -> Set<Asn1Element.Tag>,
) : SerialDescriptor by delegate {
    val leadingTags: Set<Asn1Element.Tag>
        get() = leadingTagsProvider()

    override val annotations: List<Annotation>
        get() = delegate.annotations + Asn1LeadingTagsAnnotation(leadingTagsProvider)
}

fun SerialDescriptor.withAsn1LeadingTags(leadingTags: Set<Asn1Element.Tag>): SerialDescriptor =
    Asn1LeadingTagsSerialDescriptor(this) { leadingTags }

fun SerialDescriptor.withDynamicAsn1LeadingTags(
    leadingTagsProvider: () -> Set<Asn1Element.Tag>,
): SerialDescriptor = Asn1LeadingTagsSerialDescriptor(this, leadingTagsProvider)

internal val SerialDescriptor.asn1LeadingTagsOrNull: Set<Asn1Element.Tag>?
    get() = annotations.lastOrNull { it is Asn1LeadingTagsAnnotation }
            ?.let { it as Asn1LeadingTagsAnnotation }
            ?.leadingTags
