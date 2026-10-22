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

    fun deserializeFallback(decoder: Decoder): T = runWrappingAs(a = ::SerializationException) {
        decodeFallback(decoder.decodeString())
    }

    fun serializeFallback(encoder: Encoder, value: T) = runWrappingAs(a = ::SerializationException) {
        encoder.encodeString(encodeFallback(value))
    }


    override fun deserialize(decoder: Decoder): T = deserializeFallback(decoder)

    override fun serialize(encoder: Encoder, value: T) = serializeFallback(encoder, value)
}
