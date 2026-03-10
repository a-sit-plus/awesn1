// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(at.asitplus.awesn1.InternalAwesn1Api::class)

package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.Asn1Decodable
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Encodable
import at.asitplus.awesn1.ASN1_DESCRIPTOR_OPAQUE
import at.asitplus.awesn1.encoding.decodeFromDer
import at.asitplus.awesn1.encoding.encodeToDer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Marker interface for DER-aware kotlinx.serialization encoders.
 */
interface Asn1DerEncoder : Encoder

/**
 * Marker interface for DER-aware kotlinx.serialization decoders.
 */
interface Asn1DerDecoder : Decoder

/**
 * ASN.1-specific serializer providing kotlinx-serialization support. Implement this on
 * companion objects of classes implementing [Asn1Encodable] and set it as the [Asn1Encodable]'s
 * serializer to get full kotlinx-serialization support!
 */
interface Asn1Serializable<A : Asn1Element, T : Asn1Encodable<A>> :
    Asn1Decodable<A, T>,
    KSerializer<T> {

    /**
     * Leading ASN.1 tags this serializer can decode/encode.
     *
     * Use an empty set when leading tags cannot be inferred statically.
     */
    val leadingTags: Set<Asn1Element.Tag>

    override val descriptor: SerialDescriptor
        get() = SerialDescriptor(ASN1_DESCRIPTOR_OPAQUE, ByteArraySerializer().descriptor)

    /**
     * Decodes one ASN.1-backed value via DER bytes.
     *
     * Override this when you need a non-DER fallback representation.
     */
    @Throws(SerializationException::class)
    override fun deserialize(decoder: Decoder): T {
        if (decoder !is Asn1DerDecoder) {
            throw SerializationException(
                "Serializer ${descriptor.serialName} requires an ASN.1 DER decoder."
            )
        }
        return ByteArraySerializer().deserialize(decoder).let { decodeFromDer(it) }
    }

    /**
     * Encodes one ASN.1-backed value via DER bytes.
     *
     * Override this when you need a non-DER fallback representation.
     */
    @Throws(SerializationException::class)
    override fun serialize(encoder: Encoder, value: T) {
        if (encoder !is Asn1DerEncoder) {
            throw SerializationException(
                "Serializer ${descriptor.serialName} requires an ASN.1 DER encoder."
            )
        }
        encoder.encodeSerializableValue(ByteArraySerializer(), value.encodeToDer())
    }
}

abstract class Asn1Serializer<A : Asn1Element, T : Asn1Encodable<A>>(
    override val leadingTags: Set<Asn1Element.Tag>,
    decodable: Asn1Decodable<A, T>,
    private val fallbackSerializer: KSerializer<T>? = null,
) : Asn1Serializable<A, T>, Asn1Decodable<A, T> by decodable {

    override fun deserialize(decoder: Decoder): T {
        if (decoder is Asn1DerDecoder) {
            return ByteArraySerializer().deserialize(decoder).let { decodeFromDer(it) }
        }
        return fallbackSerializer?.deserialize(decoder)
            ?: throw SerializationException(
                "Serializer ${descriptor.serialName} requires an ASN.1 DER decoder."
            )
    }

    override fun serialize(encoder: Encoder, value: T) {
        if (encoder is Asn1DerEncoder) {
            encoder.encodeSerializableValue(ByteArraySerializer(), value.encodeToDer())
            return
        }
        fallbackSerializer?.serialize(encoder, value)
            ?: throw SerializationException(
                "Serializer ${descriptor.serialName} requires an ASN.1 DER encoder."
            )
    }
}
