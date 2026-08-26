// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.viewer

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.PemBlock
import at.asitplus.awesn1.decodeFromPem
import at.asitplus.awesn1.encoding.parse
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

enum class InputFormat { AUTO, PEM, BASE64, HEX }

data class DecodedInput(
    val bytes: ByteArray,
    val element: Asn1Element,
    val detectedFormat: InputFormat,
    val pemLabel: String? = null,
)

const val MAX_INPUT_BYTES = 5 * 1024 * 1024

@OptIn(ExperimentalEncodingApi::class)
fun decodeInput(text: String, requestedFormat: InputFormat): DecodedInput {
    val source = text.trim()
    require(source.isNotEmpty()) { "Input is empty" }
    require(source.length <= MAX_INPUT_BYTES * 2 + 4096) { "Encoded input is too large" }
    val format = if (requestedFormat == InputFormat.AUTO) detectFormat(source) else requestedFormat
    val (bytes, label) = when (format) {
        InputFormat.PEM -> PemBlock.decodeFromPem(source).let { it.payload to it.pemLabel }
        InputFormat.BASE64 -> Base64.decode(source.filterNot(Char::isWhitespace)) to null
        InputFormat.HEX -> {
            val element = Asn1Element.parseFromDerHexString(source, MAX_INPUT_BYTES.toLong())
            return DecodedInput(element.derEncoded, element, InputFormat.HEX)
        }
        InputFormat.AUTO -> error("format detection failed")
    }
    require(bytes.size <= MAX_INPUT_BYTES) { "Decoded input exceeds ${MAX_INPUT_BYTES / (1024 * 1024)} MiB limit" }
    return DecodedInput(bytes, Asn1Element.parse(bytes, MAX_INPUT_BYTES.toLong()), format, label)
}

private fun detectFormat(source: String): InputFormat = when {
    PEM_BEGIN in source -> InputFormat.PEM
    runCatching { Asn1Element.parseFromDerHexString(source, MAX_INPUT_BYTES.toLong()) }.isSuccess -> InputFormat.HEX
    else -> InputFormat.BASE64
}

private const val PEM_BEGIN = "-----BEGIN "
