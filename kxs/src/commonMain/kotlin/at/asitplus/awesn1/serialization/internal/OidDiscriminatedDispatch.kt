// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.serialization.internal

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Identifiable
import at.asitplus.awesn1.ObjectIdentifier
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlin.reflect.KClass

internal sealed interface Asn1OidDiscriminatedSubtypeRegistration<T : Identifiable> {
    val serializer: KSerializer<out T>
    val runtimeClass: KClass<out T>
    val leadingTags: Set<Asn1Element.Tag>
    val debugName: String
    data class Exact<T : Identifiable>(
        override val serializer: KSerializer<out T>,
        override val runtimeClass: KClass<out T>,
        val oid: ObjectIdentifier,
        override val leadingTags: Set<Asn1Element.Tag>,
        override val debugName: String,
    ) : Asn1OidDiscriminatedSubtypeRegistration<T>

    data class CatchAll<T : Identifiable>(
        override val serializer: KSerializer<out T>,
        override val runtimeClass: KClass<out T>,
        override val leadingTags: Set<Asn1Element.Tag>,
        override val debugName: String,
    ) : Asn1OidDiscriminatedSubtypeRegistration<T>
}

/**
 * Shared strict dispatch table for OID-discriminated ASN.1 open polymorphism.
 *
 * - decode dispatches by exact ObjectIdentifier
 * - encode dispatches by runtime OID plus exact runtime type for catch-all
 * - duplicate OID registrations are rejected
 */
internal class Asn1OidDiscriminatedDispatch<T : Identifiable>(
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
     * @throws SerializationException if no registered subtype is compatible with [value]
     */
    @Throws(SerializationException::class)
    fun registrationForEncode(value: T): Asn1OidDiscriminatedSubtypeRegistration<T> {
        serializersByOid[value.oid]?.let { exactRegistration ->
            if (exactRegistration.runtimeClass.isInstance(value)) {
                return exactRegistration
            }
            throw SerializationException(
                "Registered open-polymorphic subtype for OID ${value.oid} in $serialName expects " +
                        "${exactRegistration.debugName}, but runtime value is ${value::class}"
            )
        }

        catchAllRegistration?.let { catchAll ->
            if (catchAll.runtimeClass.isInstance(value)) {
                return catchAll
            }
        }

        throw SerializationException(
            "No registered open-polymorphic subtype matches runtime value ${value::class} for $serialName"
        )
    }

}
