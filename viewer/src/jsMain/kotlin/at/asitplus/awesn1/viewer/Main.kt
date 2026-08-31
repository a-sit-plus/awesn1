// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.viewer

import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.describeAll
import kotlinx.browser.document
import kotlinx.browser.window
import org.khronos.webgl.ArrayBuffer
import org.khronos.webgl.Int8Array
import org.w3c.dom.HTMLElement
import org.w3c.dom.HTMLButtonElement
import org.w3c.dom.HTMLInputElement
import org.w3c.dom.HTMLSelectElement
import org.w3c.dom.HTMLTextAreaElement
import org.w3c.dom.events.MouseEvent
import org.w3c.files.FileReader

fun main() {
    KnownOIDs.describeAll()
    registerViewerOids()
    val input = document.getElementById("input") as HTMLTextAreaElement
    val format = document.getElementById("format") as HTMLSelectElement
    val fileInput = document.getElementById("file-input") as HTMLInputElement
    val output = document.getElementById("output")!!
    val hexOutput = document.getElementById("hex-output") as HTMLElement
    val hexMenu = document.getElementById("hex-context-menu") as HTMLElement
    val hexCopy = hexMenu.querySelector("button") as HTMLButtonElement
    val status = document.getElementById("status")!!
    val shareControl = document.getElementById("share-control") as HTMLElement
    val shareButton = document.getElementById("share") as HTMLButtonElement
    val sharePopup = document.getElementById("share-popup") as HTMLElement
    var sharePopupTimeout: Int? = null
    var pendingHex = ""
    shareButton.onclick = {
        copyText(window.location.href) { copied ->
            if (copied) {
                sharePopup.hidden = false
                sharePopupTimeout?.let { window.clearTimeout(it) }
                sharePopupTimeout = window.setTimeout({ sharePopup.hidden = true }, 2_000)
            } else status.textContent = "Could not copy viewer URL."
        }
        null
    }
    hexCopy.onclick = {
        copyText(pendingHex) { copied ->
            status.textContent = if (copied) "Copied ${pendingHex.count { it == ' ' } + 1} DER bytes as hex."
            else "Could not copy DER bytes."
        }
        hexMenu.hidden = true
        null
    }
    document.addEventListener("click", { hexMenu.hidden = true })
    fun decode() {
        shareControl.hidden = true
        sharePopup.hidden = true
        output.textContent = ""
        hexOutput.textContent = ""
        // Only the parse is allowed to fail the render: bytes that are not ASN.1 have nothing to show.
        val decoded = try {
            decodeInput(input.value, InputFormat.entries[format.selectedIndex])
        } catch (e: Throwable) {
            status.textContent = "Could not decode: ${e.describe()}"
            return
        }
        status.textContent = "Decoded ${decoded.bytes.size} bytes as ${decoded.detectedFormat}${decoded.pemLabel?.let { " ($it)" } ?: ""}" +
                if (decoded.elements.size == 1) "." else " (${decoded.elements.size} root elements)."
        try {
            val memberNames = mutableMapOf<Asn1Path, String>()
            val valueNames = mutableMapOf<Asn1Path, String>()
            decoded.elements.forEachIndexed { index, element ->
                val rootNames = schemaMemberNames(element.derEncoded, element)
                rootNames.forEach { (path, name) ->
                    memberNames[listOf(index) + path.drop(1)] = name
                }
                schemaValueNames(element, rootNames).forEach { (path, name) ->
                    valueNames[listOf(index) + path.drop(1)] = name
                }
            }
            val genericLines = genericAsn1Lines(decoded.elements, memberNames, valueNames)
            renderPrettyPrint(genericLines, decoded.bytes, output as HTMLElement)
            renderHex(decoded.elements, decoded.bytes, genericLines, hexOutput) { event, hex ->
                pendingHex = hex
                hexMenu.hidden = false
                hexMenu.style.left = "${minOf(event.clientX, window.innerWidth - hexMenu.offsetWidth - 8)}px"
                hexMenu.style.top = "${minOf(event.clientY, window.innerHeight - hexMenu.offsetHeight - 8)}px"
            }
        } catch (e: Throwable) {
            // Anything that parsed as ASN.1 renders, even if the interactive renderer trips over it.
            renderFallback(decoded, output as HTMLElement, hexOutput)
            status.textContent += " Interactive rendering failed (${e.describe()}); showing the plain tree."
        }
        val encodedInput = window.asDynamic().encodeURIComponent(input.value) as String
        window.history.replaceState(null, "", "${window.location.pathname}#$encodedInput")
        shareControl.hidden = false
        status.asDynamic().scrollIntoView(js("({ behavior: 'smooth', block: 'start' })"))
    }
    (document.getElementById("decode") as HTMLButtonElement).onclick = { decode(); null }
    (document.getElementById("open-file") as HTMLButtonElement).onclick = { fileInput.click(); null }
    fileInput.onchange = {
        val file = fileInput.files?.item(0)
        fileInput.value = ""
        if (file != null) {
            val reader = FileReader()
            reader.onload = {
                val view = Int8Array(reader.result as ArrayBuffer)
                val bytes = ByteArray(view.length) { index ->
                    (view.asDynamic()[index] as Number).toByte()
                }
                val text = runCatching { bytes.decodeToString(throwOnInvalidSequence = true) }.getOrNull()
                if (text != null && runCatching { decodeInput(text, InputFormat.AUTO) }.isSuccess) {
                    input.value = text
                    format.selectedIndex = InputFormat.AUTO.ordinal
                } else {
                    input.value = bytes.joinToString(" ") {
                        it.toUByte().toString(16).uppercase().padStart(2, '0')
                    }
                    format.selectedIndex = InputFormat.HEX.ordinal
                }
                decode()
            }
            reader.onerror = { status.textContent = "Could not read ${file.name}." }
            reader.readAsArrayBuffer(file)
        }
        null
    }
    (document.getElementById("clear") as HTMLButtonElement).onclick = {
        input.value = ""
        output.textContent = ""
        hexOutput.textContent = ""
        status.textContent = ""
        shareControl.hidden = true
        sharePopup.hidden = true
        window.history.replaceState(null, "", window.location.pathname + window.location.search)
        null
    }
    input.onkeydown = { event ->
        if (event.key == "Enter" && (event.ctrlKey || event.metaKey)) {
            decode()
            event.preventDefault()
        }
        null
    }
    fun loadLinkedInput() {
        val encoded = window.location.search.removePrefix("?").split('&')
            .firstOrNull { it.substringBefore('=') == "data" }?.substringAfter('=', "")
            ?: window.location.hash.removePrefix("#").takeIf { it.isNotEmpty() }
            ?: return
        input.value = runCatching { window.asDynamic().decodeURIComponent(encoded) as String }.getOrDefault(encoded)
        decode()
    }
    window.addEventListener("hashchange", { loadLinkedInput() })
    loadLinkedInput()
}

private fun copyText(text: String, completed: (Boolean) -> Unit) {
    fun fallback(): Boolean {
        val textarea = document.createElement("textarea") as HTMLTextAreaElement
        textarea.value = text
        textarea.style.position = "fixed"
        textarea.style.opacity = "0"
        document.body!!.appendChild(textarea)
        textarea.select()
        val copied = document.asDynamic().execCommand("copy") as Boolean
        textarea.remove()
        return copied
    }
    val clipboard = window.navigator.asDynamic().clipboard
    if (clipboard == null) completed(fallback())
    else clipboard.writeText(text).then({ completed(true) }, { completed(fallback()) })
}

private fun Throwable.describe() = message ?: this::class.simpleName ?: "unknown error"

/**
 * Last-resort rendering for input that parsed but that the interactive renderer could not lay out: the plain tree
 * from the core pretty-printer plus a raw hex dump. Both are bounded and free of schema knowledge.
 */
private fun renderFallback(decoded: DecodedInput, output: HTMLElement, hexOutput: HTMLElement) {
    output.textContent = decoded.elements.joinToString("\n") { it.prettyPrint() }
    hexOutput.textContent = decoded.bytes.take(MAX_FALLBACK_HEX_BYTES)
        .joinToString(" ") { it.toUByte().toString(16).uppercase().padStart(2, '0') } +
            if (decoded.bytes.size > MAX_FALLBACK_HEX_BYTES) "\n… hex display truncated after 64 KiB" else ""
}

private const val MAX_FALLBACK_HEX_BYTES = 64 * 1024

private fun renderPrettyPrint(lines: List<GenericAsn1Line>, der: ByteArray, output: HTMLElement) {
    val lastChildByParent = mutableMapOf<Asn1Path, Int>()
    lines.mapNotNull { it.path }.filter { it.size > 1 }.forEach { path ->
        val parent = path.dropLast(1)
        lastChildByParent[parent] = maxOf(lastChildByParent[parent] ?: -1, path.last())
    }
    lines.forEach { rendered ->
        val line = rendered.text
        val span = document.createElement("span")
        span.className = "asn1-line" + if (rendered.isRoot) " asn1-root" else ""
        rendered.path?.let { path ->
            for (level in 1..path.lastIndex) document.createElement("span").also { guide ->
                guide.className = "asn1-tree-guide " + when {
                    level == path.lastIndex -> "asn1-tree-branch"
                    path[level] < (lastChildByParent[path.take(level)] ?: path[level]) -> "asn1-tree-through"
                    else -> ""
                }
                span.appendChild(guide)
            }
        }
        val content = document.createElement("span")
        content.className = "asn1-line-content"
        span.appendChild(content)
        rendered.memberName?.let { name ->
            document.createElement("span").also {
                it.className = "asn1-member"
                it.textContent = "$name  "
                content.appendChild(it)
            }
        }
        val metadataStart = line.indexOf("  tag=")
        val tagStart = line.indexOf("tag=")
        val tagEnd = if (tagStart >= 0) line.indexOf(',', tagStart).let { if (it < 0) line.length else it } else -1
        val lengthStart = line.indexOf("length=", maxOf(tagEnd, 0))
        val lengthEnd = if (lengthStart >= 0) line.indexOf(',', lengthStart).let { if (it < 0) line.length else it } else -1
        var cursor = 0
        val coloredRanges = buildList {
            if (rendered.hasPrimitiveContent && metadataStart > 0) add(0 to metadataStart to "hex-content")
            add(tagStart to tagEnd to "hex-tag")
            add(lengthStart to lengthEnd to "hex-length")
        }
        coloredRanges.forEach { (range, cssClass) ->
            val (start, end) = range
            if (start >= 0) {
                content.appendChild(document.createTextNode(line.substring(cursor, start)))
                document.createElement("span").also {
                    it.className = cssClass
                    it.textContent = line.substring(start, end)
                    content.appendChild(it)
                }
                cursor = end
            }
        }
        content.appendChild(document.createTextNode(line.substring(cursor)))
        rendered.path?.let { path ->
            val offset = rendered.byteOffset!!
            val length = rendered.byteLength!!
            // Clamped: a re-encoded element can report a range the raw input does not cover.
            val start = offset.coerceIn(0, der.size)
            val end = minOf(offset + length, offset + 48).coerceIn(start, der.size)
            val shown = der.copyOfRange(start, end).toHexString()
            val suffix = if (length > 48) " …" else ""
            span.linkToAsn1Path(path, includeDescendants = true, view = "generic",
                detail = "DER bytes $offset..${offset + length - 1} ($length bytes)\n$shown$suffix")
        }
        output.appendChild(span)
    }
}

private fun renderHex(
    elements: List<at.asitplus.awesn1.Asn1Element>,
    der: ByteArray,
    lines: List<GenericAsn1Line>,
    output: HTMLElement,
    showContextMenu: (MouseEvent, String) -> Unit,
) {
    val (bytes, truncated) = coloredHex(elements)
    val descriptions = lines.mapNotNull { line -> line.path?.let { it to line.text.trim() } }.toMap()
    val ranges = lines.mapNotNull { line -> line.path?.let { it to (line.byteOffset!! until line.byteOffset + line.byteLength!!) } }.toMap()
    bytes.forEachIndexed { index, byte ->
        val span = document.createElement("span")
        span.className = when (byte.kind) {
            HexByteKind.TAG -> "hex-tag"
            HexByteKind.LENGTH -> "hex-length"
            HexByteKind.VALUE -> "hex-content"
        }
        span.textContent = byte.value.toUByte().toString(16).uppercase().padStart(2, '0')
        span.linkToAsn1Path(byte.path, includeDescendants = true, view = "hex",
            detail = "DER byte $index\n${descriptions[byte.path].orEmpty()}")
        span.addEventListener("contextmenu", { event ->
            event.preventDefault()
            ranges[byte.path]?.let { range ->
                val clamped = range.first.coerceIn(0, der.size) until (range.last + 1).coerceIn(0, der.size)
                showContextMenu(event as MouseEvent, der.sliceArray(clamped).joinToString(" ") {
                    it.toUByte().toString(16).uppercase().padStart(2, '0')
                })
            }
        })
        output.appendChild(span)
    }
    if (truncated) output.append("\n… hex display truncated after 64 KiB")
}

private fun org.w3c.dom.Element.linkToAsn1Path(
    path: Asn1Path, includeDescendants: Boolean, view: String, detail: String,
) {
    val encodedPath = path.joinToString(".")
    setAttribute("data-asn1-path", encodedPath)
    setAttribute("data-asn1-view", view)
    setAttribute("data-hover-detail", detail)
    addEventListener("mouseenter", { highlightAsn1Path(encodedPath, includeDescendants) })
    addEventListener("mouseleave", { highlightAsn1Path(null, false) })
}

private val highlightedElements = mutableListOf<org.w3c.dom.Element>()

private fun highlightAsn1Path(path: String?, includeDescendants: Boolean) {
    highlightedElements.forEach { it.classList.remove("asn1-highlight") }
    highlightedElements.clear()
    if (path == null) return
    val descendants = if (includeDescendants) ", #hex-output [data-asn1-path^=\"$path.\"]" else ""
    val linked = document.querySelectorAll("[data-asn1-path=\"$path\"]$descendants")
    for (index in 0 until linked.length) (linked.item(index) as? org.w3c.dom.Element)?.let {
        it.classList.add("asn1-highlight")
        highlightedElements.add(it)
    }
}
