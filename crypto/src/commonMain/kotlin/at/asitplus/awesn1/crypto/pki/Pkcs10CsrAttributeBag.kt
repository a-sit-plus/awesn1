// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.SetSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * PKCS #10 `Attributes`: programmatically created instances adhere to [Set] semantics and encode canonically, while
 * decoded values retain wire order and may even allow the same OID to be present multiple times to account for borked
 * real-world data. **YOU SHOULD NEVER HAVE TO USE THIS CLASS DIRECTLY, UNLESS FOR INSPECTION PURPOSES** but
 * instead access [Pkcs10CertificationRequestInfo.attributes] whenever dealing with CSR attributes.
 */
@Serializable(with = Pkcs10CsrAttributeBag.Serializer::class)
class Pkcs10CsrAttributeBag private constructor(
    private val elements: Collection<Pkcs10CsrAttribute>,
) : Collection<Pkcs10CsrAttribute> by elements {

    /**
     * Shallow-copies [attributes] into a new collection
     * @throws IllegalArgumentException if [attributes] are nto distinct by OID
     */
    constructor(attributes: Set<Pkcs10CsrAttribute>) : this(elements = attributes.toSet()) {
        require(distinctBy { it.oid }.size == size) { "Multiple CSR attributes with the same OID found" }
    }

    override fun equals(other: Any?): Boolean =
        this === other || other is Pkcs10CsrAttributeBag && elements.toSet() == other.elements.toSet()

    override fun hashCode(): Int = elements.toSet().hashCode()

    object Serializer : KSerializer<Pkcs10CsrAttributeBag> {
        private val listSerializer = ListSerializer(Pkcs10CsrAttribute.serializer())
        private val setSerializer = SetSerializer(Pkcs10CsrAttribute.serializer())

        override val descriptor: SerialDescriptor = SerialDescriptor(
            "at.asitplus.awesn1.crypto.pki.Pkcs10CsrAttributeBag",
            listSerializer.descriptor,
        )

        @Suppress("UNCHECKED_CAST")
        override fun serialize(encoder: Encoder, value: Pkcs10CsrAttributeBag) =
            if (value.elements is Set<*>) setSerializer.serialize(encoder, value.elements as Set<Pkcs10CsrAttribute>)
            else listSerializer.serialize(encoder, value.elements.toList())

        override fun deserialize(decoder: Decoder): Pkcs10CsrAttributeBag =
            Pkcs10CsrAttributeBag(listSerializer.deserialize(decoder))
    }
}
