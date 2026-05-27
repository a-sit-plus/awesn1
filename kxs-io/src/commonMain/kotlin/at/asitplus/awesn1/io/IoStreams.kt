// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(at.asitplus.awesn1.InternalAwesn1Api::class)

package at.asitplus.awesn1.io

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.serialization.Der
import kotlinx.serialization.*
import kotlin.reflect.typeOf

/**
 * Decodes a DER value from [source] using the inferred deserializer for [T].
 *
 * The configured [at.asitplus.awesn1.serialization.DerConfiguration.maxInputLength] is the maximum allowed total number
 * of encoded DER bytes to consume. This limit is enforced before reading or peeking from the underlying source.
 *
 * @throws SerializationException if the input does not parse as DER or violates descriptor/tag/nullability constraints.
 */
@OptIn(ExperimentalSerializationApi::class)
inline fun <reified T> Der.decodeFromSource(source: kotlinx.io.Source): T =
    decodeFromSource(
        configuration.serializersModule.serializer(typeOf<T>()),
        source,
    ) as T

/**
 * Decodes a DER value from [source] using [deserializer].
 *
 * The configured [at.asitplus.awesn1.serialization.DerConfiguration.maxInputLength] is the maximum allowed total number
 * of encoded DER bytes to consume. This limit is enforced before reading or peeking from the underlying source.
 *
 * @throws SerializationException if the input does not parse as DER or violates descriptor/tag/nullability constraints.
 */
@OptIn(ExperimentalSerializationApi::class)
fun <T> Der.decodeFromSource(
    deserializer: DeserializationStrategy<T>,
    source: kotlinx.io.Source,
): T {
    if (source.exhausted()) {
        // Keep nullable top-level semantics consistent with Der.decodeFromByteArray(empty).
        return decodeFromByteArray(deserializer, byteArrayOf())
    }
    val element = Asn1Element.parse(
        source,
        configuration.maxInputLength
            ?: throw IllegalArgumentException("For security reasons, a maximum length is required when deserializing from a Source, as the number of availably bytes is unknown beforehand")
    )
    if (!source.exhausted()) {
        throw SerializationException("Expected a single ASN.1 value in source")
    }
    return decodeFromTlv(deserializer, element)
}

@OptIn(ExperimentalSerializationApi::class)
inline fun <reified T> Der.encodeToSink(
    value: T,
    sink: kotlinx.io.Sink,
) {
    encodeToSink(
        configuration.serializersModule.serializer(typeOf<T>()),
        value,
        sink,
    )
}

@OptIn(ExperimentalSerializationApi::class)
fun <T> Der.encodeToSink(
    serializer: SerializationStrategy<T>,
    value: T,
    sink: kotlinx.io.Sink,
) {
    encodeToTlv(serializer, value)?.encodeToDer(sink)
}
