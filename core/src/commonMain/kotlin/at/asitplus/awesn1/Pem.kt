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
) {
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
}

interface PemEncodable {
    val pemLabel: String
    val pemHeaders: List<PemHeader> get() = emptyList()

    @Throws(IllegalArgumentException::class)
    fun encodeToPemPayload(): ByteArray
}

interface PemDecodable<out T> {
    @Throws(IllegalArgumentException::class)
    fun decodeFromPem(src: PemBlock): T
}

interface Asn1PemEncodable<out A : Asn1Element> : PemEncodable, Asn1Encodable<A> {
    @Throws(IllegalArgumentException::class)
    override fun encodeToPemPayload(): ByteArray =
        catchingUnwrapped { encodeToDer() }.wrapAs { IllegalArgumentException(it) }.getOrThrow()
}

interface Asn1PemDecodable<A : Asn1Element, out T : Asn1Encodable<A>> : PemDecodable<T>, Asn1Decodable<A, T> {
    @Throws(IllegalArgumentException::class)
    override fun decodeFromPem(src: PemBlock): T =
        catchingUnwrapped { decodeFromDer(src.payload) }.wrapAs { IllegalArgumentException(it) }.getOrThrow()
}

fun PemEncodable.toPemBlock(): PemBlock = PemBlock(
    label = pemLabel,
    headers = pemHeaders,
    payload = encodeToPemPayload()
)

@Throws(IllegalArgumentException::class)
fun PemEncodable.encodeToPem(): String = toPemBlock().encodeToPem()

fun PemEncodable.encodeToPemOrNull(): String? = catchingUnwrapped(::encodeToPem).getOrNull()

@JvmName("encodeAllPemEncodablesToPem")
@Throws(IllegalArgumentException::class)
fun Iterable<PemEncodable>.encodeAllToPem(): String = map { it.toPemBlock() }.encodeAllToPem()

fun Iterable<PemEncodable>.encodeAllToPemOrNull(): String? = catchingUnwrapped(::encodeAllToPem).getOrNull()

@JvmName("encodePemBlockToPem")
@Throws(IllegalArgumentException::class)
fun PemBlock.encodeToPem(): String = encodeToPem(this)

@JvmName("encodeAllPemBlocksToPem")
@Throws(IllegalArgumentException::class)
fun Iterable<PemBlock>.encodeAllToPem(): String = joinToString("\n") { it.encodeToPem() }

@JvmName("encodeToPemBlockStatic")
@Throws(IllegalArgumentException::class)
fun encodeToPem(src: PemBlock): String = catchingUnwrapped {
    require(src.label.isNotBlank()) { "PEM label must not be blank" }
    val begin = "$FENCE_PREFIX_BEGIN${src.label}$FENCE_SUFFIX"
    val end = "$FENCE_PREFIX_END${src.label}$FENCE_SUFFIX"
    val headers = src.headers.map {
        require(it.name.isNotBlank()) { "PEM header names must not be blank" }
        "${it.name}: ${it.value}"
    }
    val payloadBase64 = encodeBase64Canonical(src.payload)

    buildString {
        append(begin)
        append('\n')
        headers.forEach {
            append(it)
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
}.getOrThrow()

@JvmName("encodeAllPemBlocksToPemStatic")
@Throws(IllegalArgumentException::class)
fun encodeAllToPem(src: Iterable<PemBlock>): String = catchingUnwrapped { src.encodeAllToPem() }.getOrThrow()

@Throws(IllegalArgumentException::class)
fun <T> PemDecodable<T>.decodeFromPem(src: String): T = decodeFromPem(decodeFromPemBlock(src))

fun <T> PemDecodable<T>.decodeFromPemOrNull(src: String): T? = catchingUnwrapped { decodeFromPem(src) }.getOrNull()

@Throws(IllegalArgumentException::class)
fun <T> PemDecodable<T>.decodeAllFromPem(src: String): List<T> = decodeAllFromPemBlocks(src).map { decodeFromPem(it) }

fun <T> PemDecodable<T>.decodeAllFromPemOrNull(src: String): List<T>? =
    catchingUnwrapped { decodeAllFromPem(src) }.getOrNull()

@Throws(IllegalArgumentException::class)
fun decodeFromPem(src: String): PemBlock = decodeFromPemBlock(src)

fun decodeFromPemOrNull(src: String): PemBlock? = catchingUnwrapped { decodeFromPem(src) }.getOrNull()

@Throws(IllegalArgumentException::class)
fun decodeAllFromPem(src: String): List<PemBlock> = decodeAllFromPemBlocks(src)

fun decodeAllFromPemOrNull(src: String): List<PemBlock>? = catchingUnwrapped { decodeAllFromPem(src) }.getOrNull()

private fun decodeFromPemBlock(src: String): PemBlock = decodeAllFromPemBlocks(src).firstOrNull()
    ?: throw IllegalArgumentException("No encapsulation boundary found")

private fun decodeAllFromPemBlocks(src: String): List<PemBlock> = catchingUnwrapped {
    val lines = src.lineSequence().map { it.removeSuffix("\r") }.toList()
    val out = mutableListOf<PemBlock>()
    var idx = 0

    while (idx < lines.size) {
        val beginMatch = lines[idx].trim().takeIf(::isBeginFence)
        if (beginMatch == null) {
            idx++
            continue
        }
        val label = beginMatch.substring(FENCE_PREFIX_BEGIN.length, beginMatch.length - FENCE_SUFFIX.length)
        require(label.isNotBlank()) { "Empty PEM boundary string" }
        idx++

        val headers = mutableListOf<PemHeader>()
        var inHeaders = true
        val payloadBuilder = StringBuilder()
        var terminated = false

        while (idx < lines.size) {
            val current = lines[idx].trim()
            if (isEndFence(current)) {
                val endLabel = current.substring(FENCE_PREFIX_END.length, current.length - FENCE_SUFFIX.length)
                require(endLabel == label) { "Boundary string mismatch: $label vs $endLabel" }
                @OptIn(ExperimentalEncodingApi::class)
                val payload = Base64.Mime.decode(payloadBuilder.toString())
                out += PemBlock(label = label, headers = headers, payload = payload)
                idx++
                terminated = true
                break
            }

            if (inHeaders) {
                when {
                    current.isEmpty() -> {
                        inHeaders = false
                        idx++
                        continue
                    }

                    ':' in current -> {
                        val split = current.indexOf(':')
                        val key = current.substring(0, split).trim()
                        require(key.isNotEmpty()) { "Malformed PEM header in '$current'" }
                        val value = current.substring(split + 1).trim()
                        headers += PemHeader(key, value)
                        idx++
                        continue
                    }

                    else -> inHeaders = false
                }
            }

            if (current.isNotEmpty()) {
                payloadBuilder.append(current)
            }
            idx++
        }

        require(terminated) {
            "End of string reached while parsing block '$label' (no encapsulation terminator?)"
        }
    }

    out
}.getOrThrow()

private fun isBeginFence(line: String) = line.startsWith(FENCE_PREFIX_BEGIN) && line.endsWith(FENCE_SUFFIX)

private fun isEndFence(line: String) = line.startsWith(FENCE_PREFIX_END) && line.endsWith(FENCE_SUFFIX)

@OptIn(ExperimentalEncodingApi::class)
private fun encodeBase64Canonical(bytes: ByteArray): List<String> =
    Base64.Mime.encode(bytes)
        .lineSequence()
        .joinToString("")
        .chunked(64)
