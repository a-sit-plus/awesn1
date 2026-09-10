// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.serialization.internal

import at.asitplus.awesn1.Asn1Element
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.encoding.Encoder

internal class Asn1TagDiscriminatedOpenPolymorphicSerializer<T : Any>(
    serialName: String,
    subtypes: List<Asn1TagDiscriminatedSubtypeRegistration<T>>,
) : Asn1DiscriminatedOpenPolymorphicSerializer<T>(serialName) {

    private val dispatch = Asn1TagDiscriminatedDispatch(
        serialName = serialName,
        subtypes = subtypes,
    )

    override val leadingTags: Set<Asn1Element.Tag>
        get() = dispatch.leadingTags

    /**
     * Adds one subtype registration at runtime.
     *
     * @throws IllegalArgumentException on duplicate/invalid tag mapping
     */
    @Throws(IllegalArgumentException::class)
    fun registerSubtype(registration: Asn1TagDiscriminatedSubtypeRegistration<T>) {
        dispatch.registerSubtype(registration)
    }

    override fun selectionForEncode(value: T): DerEncodeSelection<T> =
        DerEncodeSelection(dispatch.serializerForEncode(value))

    override fun serialize(encoder: Encoder, value: T) {
        val derEncoder = encoder.requireDerEncoder(descriptor.serialName)
        val registration = dispatch.registrationForEncode(value)
        @Suppress("UNCHECKED_CAST")
        val element = derEncoder.encodeSingleElement(registration.serializer as KSerializer<T>, value)
        val encoded = when {
            element.tag in registration.leadingTags -> element
            registration.leadingTags.size == 1 -> element.withImplicitTag(registration.leadingTags.single())
            else -> throw SerializationException(
                "Subtype '${registration.debugName}' encoded leading tag ${element.tag}, " +
                        "which is not one of its registered tags ${registration.leadingTags}"
            )
        }
        derEncoder.appendElement(encoded)
    }

    /**
     * Selects decode serializer from current leading ASN.1 tag.
     *
     * @throws SerializationException when no current element exists or no subtype matches the tag
     */
    @Throws(SerializationException::class)
    override fun selectionForDecode(decoder: DerDecoder): DerDecodeSelection<T> {
        val tag = decoder.peekCurrentElementTagOrNull()
            ?: throw SerializationException("No ASN.1 element left while decoding ${descriptor.serialName}")
        val selected = dispatch.serializerForDecode(tag)
        @Suppress("UNCHECKED_CAST")
        return DerDecodeSelection(
            deserializer = selected as KSerializer<T>,
            acceptWireTag = true,
        )
    }
}
