// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(InternalAwesn1Api::class)

package at.asitplus.awesn1

import at.asitplus.awesn1.encoding.parse
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * Generic serializer for ASN.1 tree model types.
 *
 * Values are encoded as Base64 over DER bytes to keep cross-format support without requiring DER-specific runtimes.
 * When used with the `awesn1.kxs` DER format, this fallback representation is bypassed and native DER TLV
 * encoding/decoding is used.
 */
@OptIn(ExperimentalEncodingApi::class)
object Asn1ElementStringSerializer : KSerializer<Asn1Element> {
    override val descriptor = PrimitiveSerialDescriptor(ASN1_DESCRIPTOR_ELEMENT_TREE, PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): Asn1Element =
        Asn1Element.parse(Base64.decode(decoder.decodeString()))

    override fun serialize(encoder: Encoder, value: Asn1Element) {
        encoder.encodeString(Base64.encode(value.derEncoded))
    }
}
