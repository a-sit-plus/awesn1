// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.viewer

import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.describeAll
import kotlinx.browser.document
import kotlinx.browser.window
import org.w3c.dom.HTMLElement
import org.w3c.dom.HTMLButtonElement
import org.w3c.dom.HTMLSelectElement
import org.w3c.dom.HTMLTextAreaElement
import org.w3c.dom.events.MouseEvent

fun main() {
    KnownOIDs.describeAll()
    val input = document.getElementById("input") as HTMLTextAreaElement
    val format = document.getElementById("format") as HTMLSelectElement
    val output = document.getElementById("output")!!
    val hexOutput = document.getElementById("hex-output") as HTMLElement
    val hexMenu = document.getElementById("hex-context-menu") as HTMLElement
    val hexCopy = hexMenu.querySelector("button") as HTMLButtonElement
    val status = document.getElementById("status")!!
    var pendingHex = ""
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
        output.textContent = ""
        hexOutput.textContent = ""
        try {
            val decoded = decodeInput(input.value, InputFormat.entries[format.selectedIndex])
            status.textContent = "Decoded ${decoded.bytes.size} bytes as ${decoded.detectedFormat}${decoded.pemLabel?.let { " ($it)" } ?: ""}."
            val genericLines = genericAsn1Lines(decoded.element, schemaMemberNames(decoded.bytes, decoded.element))
            renderPrettyPrint(genericLines, decoded.bytes, output as HTMLElement)
            renderHex(decoded.element, decoded.bytes, genericLines, hexOutput) { event, hex ->
                pendingHex = hex
                hexMenu.hidden = false
                hexMenu.style.left = "${minOf(event.clientX, window.innerWidth - hexMenu.offsetWidth - 8)}px"
                hexMenu.style.top = "${minOf(event.clientY, window.innerHeight - hexMenu.offsetHeight - 8)}px"
            }
        } catch (e: Throwable) {
            status.textContent = "Could not decode: ${e.message ?: e::class.simpleName ?: "unknown error"}"
        }
    }
    (document.getElementById("decode") as HTMLButtonElement).onclick = { decode(); null }
    (document.getElementById("clear") as HTMLButtonElement).onclick = {
        input.value = ""
        output.textContent = ""
        hexOutput.textContent = ""
        status.textContent = ""
        null
    }
    input.onkeydown = { event ->
        if (event.key == "Enter" && (event.ctrlKey || event.metaKey)) {
            decode()
            event.preventDefault()
        }
        null
    }
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

private fun renderPrettyPrint(lines: List<GenericAsn1Line>, der: ByteArray, output: HTMLElement) {
    lines.forEach { rendered ->
        val line = rendered.text
        val span = document.createElement("span")
        span.className = "asn1-line"
        span.appendChild(document.createTextNode("  ".repeat(rendered.depth / 2)))
        rendered.memberName?.let { name ->
            document.createElement("span").also {
                it.className = "asn1-member"
                it.textContent = "$name  "
                span.appendChild(it)
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
                span.appendChild(document.createTextNode(line.substring(cursor, start)))
                document.createElement("span").also {
                    it.className = cssClass
                    it.textContent = line.substring(start, end)
                    span.appendChild(it)
                }
                cursor = end
            }
        }
        span.appendChild(document.createTextNode(line.substring(cursor)))
        rendered.path?.let { path ->
            val offset = rendered.byteOffset!!
            val length = rendered.byteLength!!
            val shown = der.copyOfRange(offset, minOf(offset + length, offset + 48)).toHexString()
            val suffix = if (length > 48) " …" else ""
            span.linkToAsn1Path(path, includeDescendants = true, view = "generic",
                detail = "DER bytes $offset..${offset + length - 1} ($length bytes)\n$shown$suffix")
        }
        output.appendChild(span)
        output.appendChild(document.createTextNode("\n"))
    }
}

private fun renderHex(
    element: at.asitplus.awesn1.Asn1Element,
    der: ByteArray,
    lines: List<GenericAsn1Line>,
    output: HTMLElement,
    showContextMenu: (MouseEvent, String) -> Unit,
) {
    val (bytes, truncated) = coloredHex(element)
    val descriptions = lines.mapNotNull { line -> line.path?.let { it to line.text.trim() } }.toMap()
    val ranges = lines.mapNotNull { line -> line.path?.let { it to (line.byteOffset!! until line.byteOffset + line.byteLength!!) } }.toMap()
    bytes.forEachIndexed { index, byte ->
        val span = document.createElement("span")
        span.className = when (byte.kind) {
            HexByteKind.TAG -> "hex-tag"
            HexByteKind.LENGTH -> "hex-length"
            HexByteKind.VALUE -> "hex-content"
        }
        span.textContent = byte.value.toUByte().toString(16).uppercase().padStart(2, '0') + " "
        span.linkToAsn1Path(byte.path, includeDescendants = true, view = "hex",
            detail = "DER byte $index\n${descriptions[byte.path].orEmpty()}")
        span.addEventListener("contextmenu", { event ->
            event.preventDefault()
            ranges[byte.path]?.let { range ->
                showContextMenu(event as MouseEvent, der.sliceArray(range).joinToString(" ") {
                    it.toUByte().toString(16).uppercase().padStart(2, '0')
                })
            }
        })
        output.appendChild(span)
    }
    if (truncated) output.append("\n… hex display truncated after 64 KiB")
}

private fun org.w3c.dom.Element.linkToAsn1Path(
    path: String, includeDescendants: Boolean, view: String, detail: String,
) {
    setAttribute("data-asn1-path", path)
    setAttribute("data-asn1-view", view)
    setAttribute("data-hover-detail", detail)
    addEventListener("mouseenter", { highlightAsn1Path(path, includeDescendants) })
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
