// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.serialization.internal

import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.serialization.Asn1LeadingTagsDescriptor
import at.asitplus.awesn1.serialization.withDynamicAsn1LeadingTags
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

internal data class DerEncodeSelection<T : Any>(
    val serializer: KSerializer<out T>,
    val discriminatorOid: ObjectIdentifier? = null,
)

internal data class DerDecodeSelection<T : Any>(
    val deserializer: DeserializationStrategy<T>,
    val acceptWireTag: Boolean = false,
    val discriminatorOid: ObjectIdentifier? = null,
)

/**
 * Shared base for ASN.1 open-polymorphic serializers that dispatch by a discriminator.
 *
 * Implementations provide:
 * - [leadingTags] for ambiguity checks
 * - encode-time serializer selection from runtime value
 * - decode-time serializer selection from current ASN.1 element
 */
internal abstract class Asn1DiscriminatedOpenPolymorphicSerializer<T : Any>(
    serialName: String,
) : KSerializer<T>, Asn1LeadingTagsDescriptor {

    final override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor(serialName, PrimitiveKind.STRING)
            .withDynamicAsn1LeadingTags { leadingTags }

    @Throws(SerializationException::class)
    protected abstract fun selectionForEncode(value: T): DerEncodeSelection<T>
    @Throws(SerializationException::class)
    protected abstract fun selectionForDecode(decoder: DerDecoder): DerDecodeSelection<T>

    /**
     * Serializes [value] using discriminator-based subtype selection.
     *
     * @throws SerializationException if encoder is not DER or subtype selection fails
     */
    @Throws(SerializationException::class)
    override fun serialize(encoder: Encoder, value: T) {
        val derEncoder = encoder.requireDerEncoder(descriptor.serialName)
        derEncoder.encodeSelectedValue(selectionForEncode(value), value)
    }

    /**
     * Deserializes one value using discriminator-based subtype selection.
     *
     * @throws SerializationException if decoder is not DER or subtype selection fails
     */
    @Throws(SerializationException::class)
    final override fun deserialize(decoder: Decoder): T {
        val derDecoder = decoder.requireDerDecoder(descriptor.serialName)
        return derDecoder.decodeCurrentElementWith(selectionForDecode(derDecoder))
    }
}
