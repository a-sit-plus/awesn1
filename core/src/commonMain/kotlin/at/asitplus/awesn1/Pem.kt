// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1

import at.asitplus.awesn1.encoding.decodeFromDer
import at.asitplus.awesn1.encoding.encodeToDer
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.jvm.JvmName

private const val FENCE_PREFIX_BEGIN = "-----BEGIN "
private const val FENCE_PREFIX_END = "-----END "
private const val FENCE_SUFFIX = "-----"

data class PemHeader(val name: String, val value: String)

data class PemBlock(
    val label: String,
    val headers: List<PemHeader> = emptyList(),
    val payload: ByteArray
) : PemEncodable {

    init {
        require(label.isNotBlank()) { "PEM label must not be blank" }
        headers.forEach {
            require(it.name.isNotBlank()) { "PEM header names must not be blank" }
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PemBlock) return false
        return label == other.label &&
                headers == other.headers &&
                payload.contentEquals(other.payload)
    }

    override fun hashCode(): Int {
        var result = label.hashCode()
        result = 31 * result + headers.hashCode()
        result = 31 * result + payload.contentHashCode()
        return result
    }

    override fun encodeToPemBlock() = this

    companion object : PemDecodable<PemBlock> {
        override fun decodeFromPemBlock(src: PemBlock): PemBlock = src
    }
}

interface PemEncodable {
    @Throws(IllegalArgumentException::class)
    fun encodeToPemBlock(): PemBlock
}

interface PemDecodable<out T> {
    @Throws(IllegalArgumentException::class)
    fun decodeFromPemBlock(src: PemBlock): T
}

interface Asn1PemEncodable<out A : Asn1Element> : PemEncodable, Asn1Encodable<A> {

    val pemLabel: String
    val pemHeaders: List<PemHeader> get() = emptyList()

    @Throws(IllegalArgumentException::class)
    override fun encodeToPemBlock(): PemBlock = try {
        PemBlock(pemLabel, pemHeaders, encodeToDer())
    } catch (x: Exception) {
        throw when (x) {
            is IllegalArgumentException -> x
            else -> IllegalArgumentException(x)
        }
    }
}

interface Asn1PemDecodable<A : Asn1Element, out T : Asn1Encodable<A>> : PemDecodable<T>, Asn1Decodable<A, T> {
    // TODO: label checking
    @Throws(IllegalArgumentException::class)
    override fun decodeFromPemBlock(src: PemBlock): T =
        catchingUnwrapped { decodeFromDer(src.payload) }.wrapAs { IllegalArgumentException(it) }.getOrThrow()
}

@Throws(IllegalArgumentException::class)
fun PemEncodable.encodeToPem(): String = encodeToPemBlock().encodeToPem()

@JvmName("encodeAllPemEncodablesToPem")
@Throws(IllegalArgumentException::class)
fun Iterable<PemEncodable>.encodeAllToPem(): String =
    map(PemEncodable::encodeToPemBlock).encodeAllToPem()

@JvmName("encodeAllPemBlocksToPem")
@Throws(IllegalArgumentException::class)
fun Iterable<PemBlock>.encodeAllToPem(): String = joinToString("\n") { it.encodeToPem() }

@JvmName("encodePemBlockToPem")
@Throws(IllegalArgumentException::class)
fun PemBlock.encodeToPem(): String {
    val begin = "$FENCE_PREFIX_BEGIN$label$FENCE_SUFFIX"
    val end = "$FENCE_PREFIX_END$label$FENCE_SUFFIX"
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
        if (headers.isNotEmpty()) {
            append('\n')
        }
        payloadBase64.forEach {
            append(it)
            append('\n')
        }
        append(end)
    }
}

@Throws(IllegalArgumentException::class)
fun <T> PemDecodable<T>.decodeFromPem(src: String): T =
    src.parseAsPemBlock().let(this::decodeFromPemBlock)

@Throws(IllegalArgumentException::class)
fun <T> PemDecodable<T>.decodeAllFromPem(src: String): List<T> =
    src.parseAsPemBlocks().map(this::decodeFromPemBlock)

@Throws(IllegalArgumentException::class)
private fun String.parseAsPemBlock(): PemBlock = parseAsPemBlocks().singleOrNull()
    ?: throw IllegalArgumentException("Multiple PEM blocks found in string")

@Throws(IllegalArgumentException::class)
private fun String.parseAsPemBlocks(): List<PemBlock> = buildList {
    val lines = lineSequence().iterator()
    while (lines.hasNext()) {
        val label = findBeginFence(lines.next()) ?: continue
        require(label.isNotBlank()) { "Empty PEM boundary string" }

        val headers = mutableListOf<PemHeader>()
        var inHeaders = true
        val payloadBuilder = StringBuilder()
        var terminated = false

        while (lines.hasNext()) {
            val current = lines.next().trim()
            findEndFence(current)?.let { endLabel ->
                require(endLabel == label) { "Boundary string mismatch: $label vs $endLabel" }
                @OptIn(ExperimentalEncodingApi::class)
                val payload = Base64.Mime.decode(payloadBuilder.toString())
                add(PemBlock(label = label, headers = headers, payload = payload))
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

private fun findBeginFence(line: String) = when {
    line.startsWith(FENCE_PREFIX_BEGIN) && line.endsWith(FENCE_SUFFIX) ->
        line.substring(FENCE_PREFIX_BEGIN.length, line.length - FENCE_SUFFIX.length)
    else -> null
}

private fun findEndFence(line: String) = when {
    line.startsWith(FENCE_PREFIX_END) && line.endsWith(FENCE_SUFFIX) ->
        line.substring(FENCE_PREFIX_END.length, line.length - FENCE_SUFFIX.length)
    else -> null
}

@OptIn(ExperimentalEncodingApi::class)
private fun ByteArray.encodeBase64Canonical(): List<String> =
    Base64.Mime.encode(this)
        .lineSequence()
        .joinToString("")
        .chunked(64)
