// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.viewer

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.PemBlock
import at.asitplus.awesn1.decodeAllFromPem
import at.asitplus.awesn1.encoding.parseAll
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

enum class InputFormat { AUTO, PEM, BASE64, HEX }

data class DecodedInput(
    val bytes: ByteArray,
    val elements: List<Asn1Element>,
    val detectedFormat: InputFormat,
    val pemLabel: String? = null,
) {
    val element: Asn1Element get() = elements.single()
}

const val MAX_INPUT_BYTES = 5 * 1024 * 1024

@OptIn(ExperimentalEncodingApi::class)
fun decodeInput(text: String, requestedFormat: InputFormat): DecodedInput {
    val source = text.trim()
    require(source.isNotEmpty()) { "Input is empty" }
    require(source.length <= MAX_INPUT_BYTES * 2 + 4096) { "Encoded input is too large" }
    val format = if (requestedFormat == InputFormat.AUTO) detectFormat(source) else requestedFormat
    val (bytes, elements, label) = when (format) {
        InputFormat.PEM -> PemBlock.decodeAllFromPem(source).let { blocks ->
            val bytes = concatenate(blocks.map(PemBlock::payload))
            Triple(bytes, blocks.flatMap { Asn1Element.parseAll(it.payload, MAX_INPUT_BYTES.toLong()) },
                blocks.map(PemBlock::pemLabel).distinct().joinToString())
        }
        InputFormat.BASE64 -> source.filterNot(Char::isWhitespace).replace('-', '+').replace('_', '/').let {
            val bytes = Base64.decode(it.padEnd((it.length + 3) / 4 * 4, '='))
            Triple(bytes, Asn1Element.parseAll(bytes, MAX_INPUT_BYTES.toLong()), null)
        }
        InputFormat.HEX -> {
            val elements = Asn1Element.parseAllFromDerHexString(source, MAX_INPUT_BYTES.toLong())
            val bytes = concatenate(elements.map(Asn1Element::derEncoded))
            Triple(bytes, elements, null)
        }
        InputFormat.AUTO -> error("format detection failed")
    }
    require(bytes.size <= MAX_INPUT_BYTES) { "Decoded input exceeds ${MAX_INPUT_BYTES / (1024 * 1024)} MiB limit" }
    return DecodedInput(bytes, elements, format, label)
}

private fun detectFormat(source: String): InputFormat = when {
    PEM_BEGIN in source -> InputFormat.PEM
    runCatching { Asn1Element.parseAllFromDerHexString(source, MAX_INPUT_BYTES.toLong()) }.isSuccess -> InputFormat.HEX
    else -> InputFormat.BASE64
}

private const val PEM_BEGIN = "-----BEGIN "

private fun concatenate(parts: List<ByteArray>): ByteArray {
    val size = parts.sumOf(ByteArray::size)
    require(size <= MAX_INPUT_BYTES) { "Decoded input exceeds ${MAX_INPUT_BYTES / (1024 * 1024)} MiB limit" }
    return ByteArray(size).also { result ->
        var offset = 0
        parts.forEach { part -> part.copyInto(result, offset).also { offset += part.size } }
    }
}
