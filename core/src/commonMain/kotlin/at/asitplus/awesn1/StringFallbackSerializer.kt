// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/** String-backed fallback serializer. Input-size policy belongs to the caller or format decoder. */
interface StringFallbackSerializer<T> : KSerializer<T> {
    fun decodeFallback(encoded: String): T

    fun encodeFallback(value: T): String

    fun deserializeFallback(decoder: Decoder): T {
        val encoded = decoder.decodeString()
        return runWrappingAs(a = { message, cause -> SerializationException(message, cause) }) {
            decodeFallback(encoded)
        }
    }

    fun serializeFallback(encoder: Encoder, value: T) {
        encoder.encodeString(
            runWrappingAs(a = { message, cause -> SerializationException(message, cause) }) { encodeFallback(value) }
        )
    }

    override fun deserialize(decoder: Decoder): T = deserializeFallback(decoder)

    override fun serialize(encoder: Encoder, value: T) = serializeFallback(encoder, value)
}
