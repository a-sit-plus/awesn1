// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1

import at.asitplus.awesn1.serialization.Asn1DerDecoder
import at.asitplus.awesn1.serialization.Asn1DerEncoder
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * String-backed fallback serializer for formats that have no ASN.1 representation, such as JSON.
 *
 * These serializers are **not usable with the ASN.1 DER format**: a string rendering of an ASN.1 value is not its DER
 * encoding, so using one with DER would emit or expect framing the format cannot round-trip. Implementations that do
 * have a DER representation — [at.asitplus.awesn1.serialization.Asn1Serializable] and friends — override [serialize]
 * and [deserialize] to handle a DER coder themselves and delegate here only for other formats.
 *
 * Input-size policy belongs to the caller or format decoder.
 */
interface StringFallbackSerializer<T> : KSerializer<T> {
    fun decodeFallback(encoded: String): T

    fun encodeFallback(value: T): String

    fun deserializeFallback(decoder: Decoder): T {
        requireNonDerFormat(decoder is Asn1DerDecoder)
        val encoded = decoder.decodeString()
        return runWrappingAs(a = { message, cause -> SerializationException(message, cause) }) {
            decodeFallback(encoded)
        }
    }

    fun serializeFallback(encoder: Encoder, value: T) {
        requireNonDerFormat(encoder is Asn1DerEncoder)
        encoder.encodeString(
            runWrappingAs(a = { message, cause -> SerializationException(message, cause) }) { encodeFallback(value) }
        )
    }

    private fun requireNonDerFormat(isDer: Boolean) {
        if (isDer) throw SerializationException(
            "${descriptor.serialName} is a non-DER fallback serializer and cannot be used with the ASN.1 DER format. " +
                    "Remove the explicit @Serializable(with = ...) so the type's own ASN.1 serializer is used, " +
                    "or keep this serializer for string-based formats only."
        )
    }

    override fun deserialize(decoder: Decoder): T = deserializeFallback(decoder)

    override fun serialize(encoder: Encoder, value: T) = serializeFallback(encoder, value)
}
