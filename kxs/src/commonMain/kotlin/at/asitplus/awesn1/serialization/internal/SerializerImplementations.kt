// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(
    at.asitplus.awesn1.InternalAwesn1Api::class,
    kotlinx.serialization.SealedSerializationApi::class,
)

package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.ASN1_DESCRIPTOR_OPAQUE
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.descriptors.SerialDescriptor

internal interface Asn1LeadingTagsDescriptor {
    val leadingTags: Set<Asn1Element.Tag>
}

private class Asn1LeadingTagsAnnotation(
    private val provider: () -> Set<Asn1Element.Tag>
) : Annotation {
    val leadingTags: Set<Asn1Element.Tag>
        get() = provider()
}

private val asn1OpaqueDelegateDescriptor: SerialDescriptor =
    SerialDescriptor(ASN1_DESCRIPTOR_OPAQUE, ByteArraySerializer().descriptor)

internal open class Asn1LeadingTagsSerialDescriptor(
    private val delegate: SerialDescriptor,
    private val leadingTagsProvider: () -> Set<Asn1Element.Tag>,
) : SerialDescriptor by delegate, Asn1LeadingTagsDescriptor {
    override val leadingTags: Set<Asn1Element.Tag>
        get() = leadingTagsProvider()

    override val annotations: List<Annotation>
        get() = delegate.annotations + Asn1LeadingTagsAnnotation(leadingTagsProvider)
}

internal class Asn1OpaqueSerializerDescriptor(
    leadingTagsProvider: () -> Set<Asn1Element.Tag>,
) : Asn1LeadingTagsSerialDescriptor(asn1OpaqueDelegateDescriptor, leadingTagsProvider)

fun SerialDescriptor.withAsn1LeadingTags(leadingTags: Set<Asn1Element.Tag>): SerialDescriptor =
    Asn1LeadingTagsSerialDescriptor(this) { leadingTags }

fun SerialDescriptor.withDynamicAsn1LeadingTags(
    leadingTagsProvider: () -> Set<Asn1Element.Tag>,
): SerialDescriptor = Asn1LeadingTagsSerialDescriptor(this, leadingTagsProvider)

internal val SerialDescriptor.asn1LeadingTagsOrNull: Set<Asn1Element.Tag>?
    get() = (this as? Asn1LeadingTagsDescriptor)?.leadingTags
        ?: annotations.lastOrNull { it is Asn1LeadingTagsAnnotation }
            ?.let { it as Asn1LeadingTagsAnnotation }
            ?.leadingTags
