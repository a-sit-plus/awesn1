// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(at.asitplus.awesn1.InternalAwesn1Api::class)

package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.InternalAwesn1Api
import kotlinx.serialization.KSerializer
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.serializer
import kotlin.reflect.KClass

@DslMarker
annotation class DefaultDerRegistryDsl

@InternalAwesn1Api
data class DefaultDerTagSubtypeRegistration<T : Any>(
    val serializer: KSerializer<out T>,
    val leadingTags: Set<Asn1Element.Tag>,
    val matches: (T) -> Boolean,
    val debugName: String,
)

@InternalAwesn1Api
data class DefaultDerTagOpenPolymorphicRegistration<T : Any>(
    val baseClass: KClass<T>,
    val serialName: String,
    val subtypes: List<DefaultDerTagSubtypeRegistration<T>>,
)

@InternalAwesn1Api
data class DefaultDerSerializersModuleRegistrySnapshot(
    val modules: List<SerializersModule>,
    val tagOpenPolymorphism: List<DefaultDerTagOpenPolymorphicRegistration<*>>,
)

@DefaultDerRegistryDsl
class DefaultDerOpenPolymorphismByTagBuilder<T : Any> internal constructor() {
    private val registrations = mutableListOf<DefaultDerTagSubtypeRegistration<T>>()

    fun <S : T> subtype(
        serializer: KSerializer<S>,
        leadingTags: Set<Asn1Element.Tag>,
        matches: (T) -> Boolean,
    ) {
        registrations += DefaultDerTagSubtypeRegistration(
            serializer = serializer,
            leadingTags = leadingTags,
            matches = matches,
            debugName = serializer.descriptor.serialName,
        )
    }

    inline fun <reified S : T> subtype(
        vararg leadingTags: Asn1Element.Tag,
        noinline matches: (T) -> Boolean = { it is S },
    ) {
        subtype(
            serializer = serializer<S>(),
            leadingTags = leadingTags.toSet(),
            matches = matches,
        )
    }

    internal fun build(): List<DefaultDerTagSubtypeRegistration<T>> = registrations.toList()
}

@InternalAwesn1Api
object InternalDefaultDerSerializersModuleRegistry {
    private val contributors = mutableListOf<SerializersModule>()
    private val tagOpenPolymorphism = mutableListOf<DefaultDerTagOpenPolymorphicRegistration<*>>()
    private var consumed = false

    fun register(module: SerializersModule) {
        check(!consumed) {
            "Default DER serializers module registry has already been consumed during default DER initialization"
        }
        contributors += module
    }

    fun <T : Any> registerTagOpenPolymorphism(
        baseClass: KClass<T>,
        serialName: String,
        block: DefaultDerOpenPolymorphismByTagBuilder<T>.() -> Unit,
    ) {
        check(!consumed) {
            "Default DER serializers module registry has already been consumed during default DER initialization"
        }
        tagOpenPolymorphism += DefaultDerTagOpenPolymorphicRegistration(
            baseClass = baseClass,
            serialName = serialName,
            subtypes = DefaultDerOpenPolymorphismByTagBuilder<T>().apply(block).build(),
        )
    }

    fun consume(): DefaultDerSerializersModuleRegistrySnapshot {
        consumed = true
        return DefaultDerSerializersModuleRegistrySnapshot(
            modules = contributors.toList(),
            tagOpenPolymorphism = tagOpenPolymorphism.toList(),
        )
    }
}
