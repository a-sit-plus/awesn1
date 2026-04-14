// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.serialization.internal

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.ObjectIdentifier
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException

internal sealed interface Asn1OidDiscriminatedSubtypeRegistration<T : Any> {
    val serializer: KSerializer<out T>
    val leadingTags: Set<Asn1Element.Tag>
    val matches: (T) -> Boolean
    val debugName: String
    data class Exact<T : Any>(
        override val serializer: KSerializer<out T>,
        val oid: ObjectIdentifier,
        override val leadingTags: Set<Asn1Element.Tag>,
        override val matches: (T) -> Boolean,
        override val debugName: String,
    ) : Asn1OidDiscriminatedSubtypeRegistration<T>

    data class CatchAll<T : Any>(
        override val serializer: KSerializer<out T>,
        override val leadingTags: Set<Asn1Element.Tag>,
        override val matches: (T) -> Boolean,
        override val debugName: String,
    ) : Asn1OidDiscriminatedSubtypeRegistration<T>
}

/**
 * Shared strict dispatch table for OID-discriminated ASN.1 open polymorphism.
 *
 * - decode dispatches by exact ObjectIdentifier
 * - encode dispatches by exactly one runtime [matches] predicate
 * - duplicate OID registrations are rejected
 */
internal class Asn1OidDiscriminatedDispatch<T : Any>(
    private val serialName: String,
    subtypes: List<Asn1OidDiscriminatedSubtypeRegistration.Exact<T>>,
    private val catchAllRegistration: Asn1OidDiscriminatedSubtypeRegistration.CatchAll<T>? = null,
) {
    private val serializersByOid = linkedMapOf<ObjectIdentifier, Asn1OidDiscriminatedSubtypeRegistration.Exact<T>>()
    private val tagsByOid = linkedMapOf<ObjectIdentifier, Set<Asn1Element.Tag>>()

    val leadingTags: Set<Asn1Element.Tag>
        get() = buildSet {
            addAll(tagsByOid.values.flatten())
            catchAllRegistration?.leadingTags?.let(::addAll)
        }

    init {
        require(subtypes.isNotEmpty()) { "At least one subtype registration is required" }
        subtypes.forEach { registration ->
            require(registration.leadingTags.isNotEmpty()) {
                "Subtype '${registration.debugName}' must declare at least one leading ASN.1 tag"
            }

            val oid = registration.oid
            val existing = serializersByOid[oid]
            if (existing != null) {
                throw IllegalArgumentException(
                    "Duplicate OID mapping for $oid in $serialName: " +
                            "${existing.serializer.descriptor.serialName} and ${registration.serializer.descriptor.serialName}"
                )
            }

            serializersByOid[oid] = registration
            tagsByOid[oid] = registration.leadingTags
        }

        catchAllRegistration?.let { registration ->
            require(registration.leadingTags.isNotEmpty()) {
                "Subtype '${registration.debugName}' must declare at least one leading ASN.1 tag"
            }
        }
    }

    fun registrationForDecodeOrNull(oid: ObjectIdentifier): Asn1OidDiscriminatedSubtypeRegistration<T>? =
        serializersByOid[oid] ?: catchAllRegistration

    @Throws(SerializationException::class)
    fun registrationForDecode(oid: ObjectIdentifier): Asn1OidDiscriminatedSubtypeRegistration<T> =
        registrationForDecodeOrNull(oid)
            ?: throw SerializationException(
                "No registered open-polymorphic subtype in $serialName for OID $oid"
            )

    /**
     * Resolves encode registration for runtime [value].
     *
     * @throws SerializationException if zero or multiple subtype matchers match [value]
     */
    @Throws(SerializationException::class)
    fun registrationForEncode(value: T): Asn1OidDiscriminatedSubtypeRegistration<T> {
        val exactMatches = serializersByOid.values.filter { it.matches(value) }
        if (exactMatches.isNotEmpty()) {
            return selectSingleEncodeMatch(exactMatches, value)
        }

        val catchAllMatches = listOfNotNull(catchAllRegistration).filter { it.matches(value) }
        return selectSingleEncodeMatch(catchAllMatches, value)
    }

    @Throws(SerializationException::class)
    private fun selectSingleEncodeMatch(
        matches: List<Asn1OidDiscriminatedSubtypeRegistration<T>>,
        value: T,
    ): Asn1OidDiscriminatedSubtypeRegistration<T> =
        when (matches.size) {
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
