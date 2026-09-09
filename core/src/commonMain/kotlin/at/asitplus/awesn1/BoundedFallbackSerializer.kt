// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

const val DEFAULT_FALLBACK_DECODING_LIMIT: Int = 384 * 1024 * 1024

/** String-backed fallback serializer with a configurable decode limit. */
interface BoundedFallbackSerializer<T> : KSerializer<T> {
    val decodingLimit: Int

    fun decodeBounded(encoded: String): T

    fun encodeBounded(value: T): String

    fun deserializeBounded(decoder: Decoder): T {
        val encoded = decoder.decodeString()
        if (encoded.length > decodingLimit) throw SerializationException(
            "Encoded ${descriptor.serialName} exceeds limit: ${encoded.length} > $decodingLimit characters"
        )
        return runWrappingAs(a = { message, cause -> SerializationException(message, cause) }) {
            decodeBounded(encoded)
        }
    }

    override fun deserialize(decoder: Decoder): T = deserializeBounded(decoder)

    fun serializeBounded(encoder: Encoder, value: T) {
        encoder.encodeString(
            runWrappingAs(a = { message, cause -> SerializationException(message, cause) }) { encodeBounded(value) }
        )
    }

    override fun serialize(encoder: Encoder, value: T) = serializeBounded(encoder, value)

    /** Returns an independent serializer with the given character limit. */
    fun bounded(decodingLimit: Int): BoundedFallbackSerializer<T> = ReboundedFallbackSerializer(this, decodingLimit)

    companion object {
        /** Default limit used by serializers without a tighter type-specific limit. */
        var defaultDecodingLimit: Int = DEFAULT_FALLBACK_DECODING_LIMIT
    }
}

private class ReboundedFallbackSerializer<T>(
    private val delegate: BoundedFallbackSerializer<T>,
    override val decodingLimit: Int,
) : BoundedFallbackSerializer<T> {
    override val descriptor: SerialDescriptor get() = delegate.descriptor
    override fun decodeBounded(encoded: String): T = delegate.decodeBounded(encoded)
    override fun encodeBounded(value: T): String = delegate.encodeBounded(value)
    override fun bounded(decodingLimit: Int): BoundedFallbackSerializer<T> =
        ReboundedFallbackSerializer(delegate, decodingLimit)
}
