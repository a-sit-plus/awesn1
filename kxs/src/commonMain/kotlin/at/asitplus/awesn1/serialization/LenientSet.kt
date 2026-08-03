// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.serialization.internal.asNamedSetDescriptor
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.encoding.decodeStructure
import kotlinx.serialization.encoding.encodeCollection

/**
 * An ASN.1 `SET OF` that retains and re-encodes malformed wire order and duplicates when decoded.
 * Programmatically created instances accept a [Set] and therefore have set semantics.
 */
@Serializable(with = LenientSet.Serializer::class)
class LenientSet<T> private constructor(
    private val elements: Collection<T>,
    private val preserveWireOrder: Boolean,
) : Collection<T> by elements {

    constructor(values: Set<T> = emptySet()) : this(elements = values.toSet(), preserveWireOrder = false)

    /** Returns these elements as a set, or throws if decoded input contained duplicates. */
    @Throws(Asn1Exception::class)
    fun toValidatedSet(): Set<T> = elements.toSet().also {
        if (it.size != size) throw Asn1Exception("ASN.1 SET OF contains duplicate elements")
    }

    override fun equals(other: Any?): Boolean =
        this === other || other is LenientSet<*> && elements.toSet() == other.elements.toSet()

    override fun hashCode(): Int = elements.toSet().hashCode()

    class Serializer<T>(private val elementSerializer: KSerializer<T>) : KSerializer<LenientSet<T>> {
        private val listDescriptor = ListSerializer(elementSerializer).descriptor
        override val descriptor: SerialDescriptor = listDescriptor.asNamedSetDescriptor(SERIAL_NAME)
        private val wireOrderDescriptor: SerialDescriptor =
            listDescriptor.asNamedSetDescriptor(SERIAL_NAME, sortChildren = false)

        override fun serialize(encoder: Encoder, value: LenientSet<T>) =
            encoder.encodeCollection(if (value.preserveWireOrder) wireOrderDescriptor else descriptor, value.size) {
                value.forEachIndexed { index, element ->
                    encodeSerializableElement(descriptor, index, elementSerializer, element)
                }
            }

        override fun deserialize(decoder: Decoder): LenientSet<T> = decoder.decodeStructure(descriptor) {
            val elements = mutableListOf<T>()
            while (true) {
                val index = decodeElementIndex(descriptor)
                if (index == CompositeDecoder.DECODE_DONE) break
                elements += decodeSerializableElement(descriptor, index, elementSerializer)
            }
            LenientSet(elements, preserveWireOrder = true)
        }

        private companion object {
            const val SERIAL_NAME = "at.asitplus.awesn1.serialization.LenientSet"
        }
    }
}
