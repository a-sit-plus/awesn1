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
 * [limit] is the maximum allowed total number of encoded DER bytes to consume; it defaults to and is **clamped to**
 * the configured [maxInputLength][at.asitplus.awesn1.serialization.DerConfiguration.maxInputLength] — a smaller [limit]
 * tightens the bound, but it can never exceed the configured maximum (mirroring how a shorter `ByteArray` lowers the
 * effective bound when decoding from bytes). The limit is enforced before reading or peeking from the underlying source.
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
 * [limit] is the maximum allowed total number of encoded DER bytes to consume; it defaults to and is **clamped to**
 * the configured [maxInputLength][at.asitplus.awesn1.serialization.DerConfiguration.maxInputLength] — a smaller [limit]
 * tightens the bound, but it can never exceed the configured maximum (mirroring how a shorter `ByteArray` lowers the
 * effective bound when decoding from bytes). The limit is enforced before reading or peeking from the underlying source.
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
    val element = Asn1Element.parse(
        source,
        minOf(limit, configuration.maxInputLength) // never overshoot the configured maximum
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
