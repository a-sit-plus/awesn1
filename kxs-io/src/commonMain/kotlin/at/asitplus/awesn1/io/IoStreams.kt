// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(at.asitplus.awesn1.InternalAwesn1Api::class)

package at.asitplus.awesn1.io

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.serialization.Der
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerializationException
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.serializer
import kotlin.reflect.typeOf

@OptIn(ExperimentalSerializationApi::class)
inline fun <reified T> Der.decodeFromSource(source: kotlinx.io.Source): T =
    decodeFromSource(
        configuration.serializersModule.serializer(typeOf<T>()),
        source,
    ) as T

@OptIn(ExperimentalSerializationApi::class)
fun <T> Der.decodeFromSource(
    deserializer: DeserializationStrategy<T>,
    source: kotlinx.io.Source,
): T {
    if (source.exhausted()) {
        // Keep nullable top-level semantics consistent with Der.decodeFromByteArray(empty).
        return decodeFromByteArray(deserializer, byteArrayOf())
    }
    val element = Asn1Element.parse(source)
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
