// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(kotlinx.serialization.ExperimentalSerializationApi::class, kotlinx.serialization.SealedSerializationApi::class)

package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.InternalAwesn1Api
import kotlinx.serialization.descriptors.SerialDescriptor

/**
 * Carries a serializer's declared leading ASN.1 tags on its [SerialDescriptor].
 *
 * A `SerialDescriptor` is the only thing an ASN.1 format sees at analysis time, so a serializer that knows which
 * leading tags it emits and accepts has to publish that fact here for the format to use it. Without it the format
 * can only infer tags from the descriptor's serial name and kind, which over-approximates whenever several
 * distinct wire contracts share one serial name — as the concrete [at.asitplus.awesn1.Asn1String] subtypes do.
 *
 * The tags travel as an annotation rather than as a marker interface so that they survive descriptor delegation,
 * including kotlinx's nullable wrapper.
 */
private class Asn1LeadingTagsAnnotation(
    private val provider: () -> Set<Asn1Element.Tag>
) : Annotation {
    val leadingTags: Set<Asn1Element.Tag>
        get() = provider()
}

private class Asn1LeadingTagsSerialDescriptor(
    private val delegate: SerialDescriptor,
    private val leadingTagsProvider: () -> Set<Asn1Element.Tag>,
) : SerialDescriptor by delegate {
    override val annotations: List<Annotation>
        get() = delegate.annotations + Asn1LeadingTagsAnnotation(leadingTagsProvider)
}

/**
 * Declares the leading ASN.1 tags this descriptor's values can start with.
 *
 * An empty set means "cannot be inferred statically", which ASN.1 formats treat as undecidable rather than as
 * "no tags".
 */
fun SerialDescriptor.withAsn1LeadingTags(leadingTags: Set<Asn1Element.Tag>): SerialDescriptor =
    Asn1LeadingTagsSerialDescriptor(this) { leadingTags }

/**
 * Declares leading ASN.1 tags that are only known later, such as an open-polymorphic dispatch table that
 * subtypes register into after the descriptor is built.
 */
fun SerialDescriptor.withDynamicAsn1LeadingTags(
    leadingTagsProvider: () -> Set<Asn1Element.Tag>,
): SerialDescriptor = Asn1LeadingTagsSerialDescriptor(this, leadingTagsProvider)

/** The tags declared through [withAsn1LeadingTags]/[withDynamicAsn1LeadingTags], or `null` if none were. */
@InternalAwesn1Api
val SerialDescriptor.asn1LeadingTagsOrNull: Set<Asn1Element.Tag>?
    get() = annotations.lastOrNull { it is Asn1LeadingTagsAnnotation }
        ?.let { it as Asn1LeadingTagsAnnotation }
        ?.leadingTags
