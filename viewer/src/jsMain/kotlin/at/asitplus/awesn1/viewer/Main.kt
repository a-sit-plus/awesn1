// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.viewer

import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.describeAll
import kotlinx.browser.document
import org.w3c.dom.HTMLElement
import org.w3c.dom.HTMLButtonElement
import org.w3c.dom.HTMLSelectElement
import org.w3c.dom.HTMLTextAreaElement

fun main() {
    KnownOIDs.describeAll()
    val input = document.getElementById("input") as HTMLTextAreaElement
    val format = document.getElementById("format") as HTMLSelectElement
    val output = document.getElementById("output")!!
    val hexOutput = document.getElementById("hex-output") as HTMLElement
    val cryptoOutput = document.getElementById("crypto-output")!!
    val status = document.getElementById("status")!!
    fun decode() {
        output.textContent = ""
        hexOutput.textContent = ""
        cryptoOutput.textContent = ""
        try {
            val decoded = decodeInput(input.value, InputFormat.entries[format.selectedIndex])
            status.textContent = "Decoded ${decoded.bytes.size} bytes as ${decoded.detectedFormat}${decoded.pemLabel?.let { " ($it)" } ?: ""}."
            renderPrettyPrint(decoded.element.prettyPrint(limit = 250_000), decoded.element, output as HTMLElement)
            renderHex(decoded.element, hexOutput)
            cryptoOutput.textContent = renderCryptoTypes(decoded.bytes).ifEmpty { "No supported crypto structure matched." }
        } catch (e: Throwable) {
            status.textContent = "Could not decode: ${e.message ?: e::class.simpleName ?: "unknown error"}"
        }
    }
    (document.getElementById("decode") as HTMLButtonElement).onclick = { decode(); null }
    (document.getElementById("clear") as HTMLButtonElement).onclick = {
        input.value = ""
        output.textContent = ""
        hexOutput.textContent = ""
        cryptoOutput.textContent = ""
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

private fun renderPrettyPrint(text: String, element: at.asitplus.awesn1.Asn1Element, output: HTMLElement) {
    val paths = elementPaths(element).iterator()
    text.lineSequence().forEach { line ->
        val span = document.createElement("span")
        span.className = "hex-value-${(line.length - line.trimStart().length) / 2 % 6}"
        val tagStart = line.indexOf("tag=")
        val tagEnd = if (tagStart >= 0) line.indexOf(',', tagStart).let { if (it < 0) line.length else it } else -1
        val lengthStart = line.indexOf("length=", maxOf(tagEnd, 0))
        val lengthEnd = if (lengthStart >= 0) line.indexOf(',', lengthStart).let { if (it < 0) line.length else it } else -1
        var cursor = 0
        listOf(tagStart to tagEnd to "hex-tag", lengthStart to lengthEnd to "hex-length").forEach { (range, cssClass) ->
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
        if (tagStart >= 0 && paths.hasNext()) span.linkToAsn1Path(paths.next(), includeDescendants = true, view = "generic")
        output.appendChild(span)
        output.appendChild(document.createTextNode("\n"))
    }
}

private fun renderHex(element: at.asitplus.awesn1.Asn1Element, output: HTMLElement) {
    val (bytes, truncated) = coloredHex(element)
    bytes.forEachIndexed { index, byte ->
        val span = document.createElement("span")
        span.className = when (byte.kind) {
            HexByteKind.TAG -> "hex-tag"
            HexByteKind.LENGTH -> "hex-length"
            HexByteKind.VALUE -> "hex-value-${byte.depth % 6}"
        }
        span.textContent = byte.value.toUByte().toString(16).uppercase().padStart(2, '0') + " "
        span.linkToAsn1Path(byte.path, includeDescendants = false, view = "hex")
        output.appendChild(span)
        if ((index + 1) % 16 == 0) output.appendChild(document.createElement("br"))
    }
    if (truncated) output.append("\n… hex display truncated after 64 KiB")
}

private fun org.w3c.dom.Element.linkToAsn1Path(path: String, includeDescendants: Boolean, view: String) {
    setAttribute("data-asn1-path", path)
    setAttribute("data-asn1-view", view)
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
