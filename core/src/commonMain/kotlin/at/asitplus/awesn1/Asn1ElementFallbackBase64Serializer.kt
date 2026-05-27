// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(InternalAwesn1Api::class)

package at.asitplus.awesn1

import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.encoding.parseAll
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
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
abstract class Asn1ElementFallbackBase64SerializerBase<T : Any>(
    private val decodeElement: (Asn1Element) -> T,
    private val encodeElement: (T) -> Asn1Element
) : KSerializer<T> {
    override val descriptor: SerialDescriptor = ASN1_ELEMENT_FALLBACK_BASE64_DESCRIPTOR

    fun decodeFromAsn1Element(element: Asn1Element): T = decodeElement(element)

    override fun deserialize(decoder: Decoder): T =
        decodeFromAsn1Element(Asn1Element.parse(Base64.decode(decoder.decodeString())))

    override fun serialize(encoder: Encoder, value: T) {
        encoder.encodeString(Base64.encode(encodeElement(value).derEncoded))
    }
}

@OptIn(ExperimentalEncodingApi::class)
object Asn1ElementFallbackBase64Serializer : Asn1ElementFallbackBase64SerializerBase<Asn1Element>(
    decodeElement = { it },
    encodeElement = { it }
)

@OptIn(ExperimentalEncodingApi::class)
object Asn1StructureFallbackBase64Serializer : Asn1ElementFallbackBase64SerializerBase<Asn1Structure>(
    decodeElement = { it.asStructureOrCustomPrimitiveStructure() },
    encodeElement = { it }
)

@OptIn(ExperimentalEncodingApi::class)
object Asn1ExplicitlyTaggedFallbackBase64Serializer :
    Asn1ElementFallbackBase64SerializerBase<Asn1ExplicitlyTagged>(
        decodeElement = { it.asExplicitlyTagged() },
        encodeElement = { it }
    )

@OptIn(ExperimentalEncodingApi::class)
object Asn1SequenceFallbackBase64Serializer : Asn1ElementFallbackBase64SerializerBase<Asn1Sequence>(
    decodeElement = { it.asSequence() },
    encodeElement = { it }
)

@OptIn(ExperimentalEncodingApi::class)
object Asn1CustomStructureFallbackBase64Serializer : Asn1ElementFallbackBase64SerializerBase<Asn1CustomStructure>(
    decodeElement = { it.asCustomStructure() },
    encodeElement = { it }
)

@OptIn(ExperimentalEncodingApi::class)
object Asn1EncapsulatingOctetStringFallbackBase64Serializer :
    Asn1ElementFallbackBase64SerializerBase<Asn1EncapsulatingOctetString>(
        decodeElement = { it.asEncapsulatingOctetString() },
        encodeElement = { it }
    )

@OptIn(ExperimentalEncodingApi::class)
object Asn1OctetStringFallbackBase64Serializer :
    Asn1ElementFallbackBase64SerializerBase<Asn1OctetString>(
        decodeElement = { it as Asn1OctetString },
        encodeElement = { it }
    )

@OptIn(ExperimentalEncodingApi::class)
object Asn1SetFallbackBase64Serializer : Asn1ElementFallbackBase64SerializerBase<Asn1Set>(
    decodeElement = { it.asSet() },
    encodeElement = { it }
)

@OptIn(ExperimentalEncodingApi::class)
object Asn1SetOfFallbackBase64Serializer : Asn1ElementFallbackBase64SerializerBase<Asn1SetOf>(
    decodeElement = { Asn1SetOf(it.asSet().children) },
    encodeElement = { it }
)

@OptIn(ExperimentalEncodingApi::class)
object Asn1PrimitiveFallbackBase64Serializer : Asn1ElementFallbackBase64SerializerBase<Asn1Primitive>(
    decodeElement = { it.asPrimitive() },
    encodeElement = { it }
)

private val ASN1_ELEMENT_FALLBACK_BASE64_DESCRIPTOR =
    PrimitiveSerialDescriptor(ASN1_DESCRIPTOR_ELEMENT_TREE, PrimitiveKind.STRING)

private fun Asn1Element.asStructureOrCustomPrimitiveStructure(): Asn1Structure =
    when (this) {
        is Asn1Structure -> this
        is Asn1Primitive -> asCustomPrimitiveStructure()
    }

private fun Asn1Element.asCustomStructure(): Asn1CustomStructure =
    when (this) {
        is Asn1CustomStructure -> this
        is Asn1Structure -> Asn1CustomStructure(children, tag.tagValue, tag.tagClass)
        is Asn1Primitive -> asCustomPrimitiveStructure()
    }

private fun Asn1Primitive.asCustomPrimitiveStructure(): Asn1CustomStructure =
    Asn1CustomStructure.asPrimitive(
        children = Asn1Element.parseAll(content),
        tag = tag.tagValue,
        tagClass = tag.tagClass
    )
