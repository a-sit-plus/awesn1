// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.serialization.internal

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.Asn1Structure
import at.asitplus.awesn1.Identifiable
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.readOid
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Encoder

internal class Asn1OidDiscriminatedOpenPolymorphicSerializer<T : Identifiable>(
    serialName: String,
    subtypes: List<Asn1OidDiscriminatedSubtypeRegistration.Exact<T>>,
    catchAll: Asn1OidDiscriminatedSubtypeRegistration.CatchAll<T>? = null,
    private val oidSelector: (Asn1Element) -> ObjectIdentifier? = ::oidFrom,
) : Asn1DiscriminatedOpenPolymorphicSerializer<T>(serialName) {

    private val dispatch = Asn1OidDiscriminatedDispatch(
        serialName = serialName,
        subtypes = subtypes,
        catchAllRegistration = catchAll,
    )

    override val leadingTags: Set<Asn1Element.Tag>
        get() = dispatch.leadingTags

    override fun serializerForEncode(encoder: DerEncoder, value: T): KSerializer<out T> {
        val reg = dispatch.registrationForEncode(value)
        // Exact subtypes carry no OID of their own → inject the discriminator as the leading element.
        // The catch-all (fallback) carries its OID as its own first field, so injecting would write it
        // twice; emit it exactly once and let the fallback round-trip it into that property.
        if (reg is Asn1OidDiscriminatedSubtypeRegistration.Exact) encoder.prependOidToNextStructure(value.oid)
        return reg.serializer
    }

    /**
     * Selects decode serializer by extracting discriminator OID from current ASN.1 element.
     *
     * @throws SerializationException if no current element exists, OID extraction fails, or no subtype is registered
     */
    @Throws(SerializationException::class)
    override fun serializerForDecode(decoder: DerDecoder): DeserializationStrategy<T> {
        val element = decoder.peekCurrentElementOrNull()
            ?: throw SerializationException("No ASN.1 element left while decoding ${descriptor.serialName}")
        val oid = oidSelector(element)
            ?: throw SerializationException(
                "Could not extract discriminator OID from current ASN.1 element while decoding ${descriptor.serialName}"
            )
        val reg = dispatch.registrationForDecode(oid)
        // Mirror of encode: drop the injected discriminator only for exact subtypes. For the catch-all
        // the leading OID IS the fallback's own `oid` field — keep it so the fallback reads it back.
        if (reg is Asn1OidDiscriminatedSubtypeRegistration.Exact) decoder.dropOidFromNextStructure()
        @Suppress("UNCHECKED_CAST")
        return reg.serializer as DeserializationStrategy<T>
    }

    /**
     * Serializes [value] and prepends OID discriminator to the next encoded structure.
     *
     * @throws SerializationException if encoder is not DER or runtime subtype matching is ambiguous/missing
     */
    @Throws(SerializationException::class)
    override fun serialize(encoder: Encoder, value: T) {
        val derEncoder = encoder as? DerEncoder
            ?: throw SerializationException("Expected DerEncoder while encoding ${descriptor.serialName}")

        val reg = dispatch.registrationForEncode(value)
        // See serializerForEncode: inject the discriminator only for exact (sans-OID) subtypes; the
        // catch-all already carries its OID as its first field, so it is encoded exactly once.
        if (reg is Asn1OidDiscriminatedSubtypeRegistration.Exact) derEncoder.prependOidToNextStructure(value.oid)

        @Suppress("UNCHECKED_CAST")
        val ser = reg.serializer as KSerializer<T>
        derEncoder.encodeSerializableValue(ser, value)
    }


}

/**
 * Default OID selector for OID-discriminated open polymorphism.
 *
 * This covers the common shape `SEQUENCE { OBJECT IDENTIFIER, ... }`
 */
internal fun oidFrom(element: Asn1Element): ObjectIdentifier? {

    val structure = element as? Asn1Structure ?: return null

    val primitive = structure.firstOrNull() as? Asn1Primitive
    if (primitive?.tag == Asn1Element.Tag.OID) {
        return runCatching { primitive.readOid() }.getOrNull()
    }


    return null
}

internal fun inferOpenPolymorphicSubtypeLeadingTagsOrNull(
    descriptor: SerialDescriptor,
): Set<Asn1Element.Tag>? = when (val resolution = descriptor.possibleLeadingTagsForAsn1()) {
    is Asn1LeadingTagsResolution.Exact -> resolution.tags
    Asn1LeadingTagsResolution.UnknownInfer -> null
}

internal fun cannotInferOpenPolymorphicSubtypeLeadingTagsMessage(
    serialName: String,
): String =
    "Cannot infer leading ASN.1 tag(s) for subtype '$serialName'. " +
            "Provide leadingTags explicitly."
