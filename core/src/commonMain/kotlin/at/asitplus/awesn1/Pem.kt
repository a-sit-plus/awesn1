// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1

import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.jvm.JvmName

private const val FENCE_PREFIX_BEGIN = "-----BEGIN "
private const val FENCE_PREFIX_END = "-----END "
private const val FENCE_SUFFIX = "-----"

data class PemHeader(val name: String, val value: String) {
    init {
        require(FENCE_PREFIX_BEGIN !in name && FENCE_PREFIX_END !in name) {
            "PEM header names must not contain PEM fences"
        }
        require(FENCE_PREFIX_BEGIN !in value && FENCE_PREFIX_END !in value) {
            "PEM header values must not contain PEM fences"
        }
    }
}

data class PemBlock(
    val pemLabel: String,
    val headers: Iterable<PemHeader> = emptyList(),
    val payload: ByteArray
) {

    init {
        require(pemLabel.isNotBlank()) { "PEM label must not be blank" }
        require(pemLabel.all { it in ' '..'~' }) { "PEM label must contain only printable ASCII characters" }
        headers.forEach {
            require(it.name.isNotBlank()) { "PEM header names must not be blank" }
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PemBlock) return false
        return pemLabel == other.pemLabel &&
                headers == other.headers &&
                payload.contentEquals(other.payload)
    }

    override fun hashCode(): Int {
        var result = pemLabel.hashCode()
        result = 31 * result + headers.hashCode()
        result = 31 * result + payload.contentHashCode()
        return result
    }

    fun encodeToPem(): String {
        val begin = "$FENCE_PREFIX_BEGIN$pemLabel$FENCE_SUFFIX"
        val end = "$FENCE_PREFIX_END$pemLabel$FENCE_SUFFIX"
        val payloadBase64 = payload.encodeBase64Canonical()

        return buildString {
            append(begin)
            append('\n')
            headers.forEach {
                append(it.name)
                append(':')
                append(it.value)
                append('\n')
            }
            if (headers.any()) {
                append('\n')
            }
            payloadBase64.forEach {
                append(it)
                append('\n')
            }
            append(end)
        }
    }

    companion object
}

@JvmName("encodeAllPemBlocksToPem")
@Throws(IllegalArgumentException::class)
fun Iterable<PemBlock>.encodeAllToPem(): String = joinToString("\n") { it.encodeToPem() }

@Throws(IllegalArgumentException::class)
fun PemBlock.Companion.decodeFromPem(src: String) =
    src.parseAsPemBlock()

@Throws(IllegalArgumentException::class)
fun PemBlock.Companion.decodeAllFromPem(src: String): List<PemBlock> =
    src.parseAsPemBlocks()

@Throws(IllegalArgumentException::class)
private fun String.parseAsPemBlock(): PemBlock =
    parseAsPemBlocks().singleOrNull()
        /** parseAsPemBlocks() always returns nonempty */
        ?: throw IllegalArgumentException("Multiple PEM blocks found in string")

@Throws(IllegalArgumentException::class)
private fun String.parseAsPemBlocks(): List<PemBlock> = buildList {
    val lines = lineSequence()
        .map(String::trim) //trim per line
        .iterator()

    while (lines.hasNext()) {
        //consume lines in helper until found
        val label = findBeginFence(lines.next()) ?: continue
        require(label.isNotBlank()) { "Empty PEM boundary string" }

        val headers = mutableListOf<PemHeader>()
        var inHeaders = true
        val payloadBuilder = StringBuilder()
        var terminated = false

        while (lines.hasNext()) {
            val current = lines.next()

            findEndFence(current)?.let { endLabel ->
                require(endLabel == label) { "Boundary string mismatch: $label vs $endLabel" }
                @OptIn(ExperimentalEncodingApi::class)
                val payload = PemBase64.decode(payloadBuilder.toString())

                add(PemBlock(pemLabel = label, headers = headers, payload = payload))
                terminated = true
                break
            }

            if (inHeaders) {
                when {
                    current.isEmpty() -> {
                        inHeaders = false
                        continue
                    }

                    ':' in current -> {
                        val split = current.indexOf(':')
                        val key = current.substring(0, split).trim()
                        require(key.isNotEmpty()) { "Malformed PEM header in '$current'" }
                        val value = current.substring(split + 1).trim()
                        headers += PemHeader(key, value)
                        continue
                    }

                    else -> inHeaders = false
                }
            }

            if (current.isNotEmpty()) {
                payloadBuilder.append(current)
            }
        }

        require(terminated) {
            "End of string reached while parsing block '$label' (no encapsulation terminator?)"
        }
    }
}.ifEmpty { throw IllegalArgumentException("No PEM blocks found in string") }

private fun findBeginFence(line: String): String? = when {
    line.startsWith(FENCE_PREFIX_BEGIN) && line.endsWith(FENCE_SUFFIX) ->
        line.substring(FENCE_PREFIX_BEGIN.length, line.length - FENCE_SUFFIX.length).trim()

    else -> null
}

private fun findEndFence(line: String): String? = when {
    line.startsWith(FENCE_PREFIX_END) && line.endsWith(FENCE_SUFFIX) ->
        line.substring(FENCE_PREFIX_END.length, line.length - FENCE_SUFFIX.length).trim()

    else -> null
}

@OptIn(ExperimentalEncodingApi::class)
private val PemBase64: Base64 =
    Base64.Mime.withPadding(Base64.PaddingOption.PRESENT_OPTIONAL)

@OptIn(ExperimentalEncodingApi::class)
private fun ByteArray.encodeBase64Canonical(): List<String> =
    Base64.Default.encode(this).chunked(64)
