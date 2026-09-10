// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.serialization.internal

import at.asitplus.awesn1.Asn1Element
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException

internal data class Asn1TagDiscriminatedSubtypeRegistration<T : Any>(
    val serializer: KSerializer<out T>,
    val leadingTags: Set<Asn1Element.Tag>,
    val matches: (T) -> Boolean = { false },
    val debugName: String,
)

/**
 * Shared strict dispatch table for tag-discriminated ASN.1 polymorphism.
 *
 * - decode dispatches by exact leading tag
 * - encode dispatches by exactly one runtime match
 * - duplicate tag registrations are rejected
 */
internal class Asn1TagDiscriminatedDispatch<T : Any>(
    private val serialName: String,
    subtypes: List<Asn1TagDiscriminatedSubtypeRegistration<T>>,
) {
    private val registrations = subtypes.toList()
    private val serializersByTag: Map<Asn1Element.Tag, KSerializer<out T>> = buildMap {
        require(registrations.isNotEmpty()) { "At least one subtype registration is required" }
        registrations.forEach { registration ->
            require(registration.leadingTags.isNotEmpty()) {
                "Subtype '${registration.debugName}' must declare at least one leading ASN.1 tag"
            }
            registration.leadingTags.forEach { tag ->
                val existing = put(tag, registration.serializer)
                if (existing != null) {
                    throw IllegalArgumentException(
                        "Duplicate tag mapping for $tag in $serialName: " +
                                "${existing.descriptor.serialName} and ${registration.serializer.descriptor.serialName}"
                    )
                }
            }
        }
    }

    val leadingTags: Set<Asn1Element.Tag>
        get() = serializersByTag.keys

    fun serializerForDecodeOrNull(tag: Asn1Element.Tag): KSerializer<out T>? =
        serializersByTag[tag]

    /**
     * Resolves decode serializer for [tag].
     *
     * @throws SerializationException if no subtype is registered for [tag]
     */
    @Throws(SerializationException::class)
    fun serializerForDecode(tag: Asn1Element.Tag): KSerializer<out T> =
        serializerForDecodeOrNull(tag)
            ?: throw SerializationException(
                "No registered open-polymorphic subtype in $serialName for leading tag $tag"
            )

    fun registrationForEncode(value: T): Asn1TagDiscriminatedSubtypeRegistration<T> {
        val matches = registrations.filter { it.matches(value) }
        return when (matches.size) {
            1 -> matches.single()
            0 -> throw SerializationException(
                "No registered open-polymorphic subtype matches runtime value ${value::class} for $serialName"
            )

            else -> throw SerializationException(
                "Multiple registered open-polymorphic subtypes match runtime value ${value::class} " +
                        "for $serialName: ${matches.joinToString { it.debugName }}"
            )
        }
    }

}
