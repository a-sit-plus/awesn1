// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.viewer

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1EncapsulatingOctetString
import at.asitplus.awesn1.Asn1Structure

enum class HexByteKind { TAG, LENGTH, VALUE }

data class ColoredHexByte(val value: Byte, val kind: HexByteKind, val depth: Int, val path: String)

private const val MAX_RENDERED_HEX_BYTES = 64 * 1024

fun coloredHex(element: Asn1Element): Pair<List<ColoredHexByte>, Boolean> {
    val result = ArrayList<ColoredHexByte>(minOf(element.overallLength, MAX_RENDERED_HEX_BYTES))
    val stack = ArrayDeque<Triple<Asn1Element, Int, String>>().apply { addLast(Triple(element, 0, "0")) }
    while (stack.isNotEmpty() && result.size < MAX_RENDERED_HEX_BYTES) {
        val (current, depth, path) = stack.removeLast()
        current.tag.encodedTag.forEach { result.add(ColoredHexByte(it, HexByteKind.TAG, depth, path)) }
        current.encodedLength.forEach { result.add(ColoredHexByte(it, HexByteKind.LENGTH, depth, path)) }
        val children = current.childrenOrNull()
        if (children == null) {
            val headerSize = current.tag.encodedTag.size + current.encodedLength.size
            current.derEncoded.drop(headerSize).forEach { result.add(ColoredHexByte(it, HexByteKind.VALUE, depth, path)) }
        } else {
            for (index in children.indices.reversed()) stack.addLast(Triple(children[index], depth + 1, "$path.$index"))
        }
    }
    // ponytail: cap DOM nodes; use canvas rendering if full multi-megabyte hex output becomes necessary.
    return result.take(MAX_RENDERED_HEX_BYTES) to (element.overallLength > MAX_RENDERED_HEX_BYTES)
}

fun elementPaths(element: Asn1Element): List<String> = buildList {
    val stack = ArrayDeque<Pair<Asn1Element, String>>().apply { addLast(element to "0") }
    while (stack.isNotEmpty()) {
        val (current, path) = stack.removeLast()
        add(path)
        (current as? Asn1Structure)?.children?.let { children ->
            for (index in children.indices.reversed()) stack.addLast(children[index] to "$path.$index")
        }
    }
}

private fun Asn1Element.childrenOrNull() = when (this) {
    is Asn1Structure -> children
    is Asn1EncapsulatingOctetString -> children
    else -> null
}
