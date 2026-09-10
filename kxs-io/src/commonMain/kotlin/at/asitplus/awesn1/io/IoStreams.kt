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
 * [limit] is the per-call maximum number of encoded DER bytes to consume. It defaults to and cannot exceed
 * [DerConfiguration.maxInputLength][at.asitplus.awesn1.serialization.DerConfiguration.maxInputLength], whose default
 * is the target's `ByteArray` ceiling. The effective limit is enforced before reading or peeking from [source].
 *
 * @throws SerializationException if the input does not parse as DER or violates descriptor/tag/nullability constraints.
 */
@OptIn(ExperimentalSerializationApi::class)
inline fun <reified T> Der.decodeFromSource(
    source: kotlinx.io.Source,
    limit: Long = configuration.maxInputLength,
): T =
    decodeFromSource(
        configuration.serializersModule.serializer(typeOf<T>()),
        source,
        limit,
    ) as T

/**
 * Decodes a DER value from [source] using [deserializer].
 *
 * [limit] is the per-call maximum number of encoded DER bytes to consume. It defaults to and cannot exceed
 * [DerConfiguration.maxInputLength][at.asitplus.awesn1.serialization.DerConfiguration.maxInputLength], whose default
 * is the target's `ByteArray` ceiling. The effective limit is enforced before reading or peeking from [source].
 *
 * @throws SerializationException if the input does not parse as DER or violates descriptor/tag/nullability constraints.
 */
@OptIn(ExperimentalSerializationApi::class)
fun <T> Der.decodeFromSource(
    deserializer: DeserializationStrategy<T>,
    source: kotlinx.io.Source,
    limit: Long = configuration.maxInputLength,
): T {
    if (source.exhausted()) {
        // Keep nullable top-level semantics consistent with Der.decodeFromByteArray(empty).
        return decodeFromByteArray(deserializer, byteArrayOf())
    }
    val element = Asn1Element.parse(source, minOf(limit, configuration.maxInputLength))
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
