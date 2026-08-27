// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.viewer

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1EncapsulatingOctetString
import at.asitplus.awesn1.Asn1Structure

enum class HexByteKind { TAG, LENGTH, VALUE }

data class ColoredHexByte(val value: Byte, val kind: HexByteKind, val depth: Int, val path: String)
data class GenericAsn1Line(
    val text: String,
    val depth: Int,
    val path: String? = null,
    val byteOffset: Int? = null,
    val byteLength: Int? = null,
    val memberName: String? = null,
)

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

fun genericAsn1Lines(element: Asn1Element, memberNames: Map<String, String> = emptyMap()): List<GenericAsn1Line> = buildList {
    data class Pending(val element: Asn1Element, val depth: Int, val path: String, val offset: Int)
    val stack = ArrayDeque<Pending>().apply { addLast(Pending(element, 0, "0", 0)) }
    while (stack.isNotEmpty()) {
        val (current, depth, path, offset) = stack.removeLast()
        add(GenericAsn1Line(current.friendlyHeader(), depth, path, offset, current.overallLength, memberNames[path]))
        current.childrenOrNull()?.let { children ->
            var childOffset = offset + current.tag.encodedTag.size + current.encodedLength.size
            val offsets = children.map { child -> childOffset.also { childOffset += child.overallLength } }
            for (index in children.indices.reversed()) {
                stack.addLast(Pending(children[index], depth + 2, "$path.$index", offsets[index]))
            }
        }
    }
}

private fun Asn1Element.friendlyHeader(): String {
    val children = childrenOrNull()
    val type = when {
        this is Asn1EncapsulatingOctetString -> "OCTET STRING (${contentLengthLong} byte${if (contentLengthLong == 1L) "" else "s"})"
        children != null && tag == Asn1Element.Tag.SEQUENCE -> "SEQUENCE (${children.size} elem)"
        children != null && tag == Asn1Element.Tag.SET -> "SET (${children.size} elem)"
        children != null -> "[${tag.tagValue}] (${children.size} elem)"
        else -> tag.toString().substringAfterLast('(').substringBefore(')') + primitiveValue()
    }
    return "$type  tag=$tag, length=$contentLengthLong"
}

private fun Asn1Element.primitiveValue(): String {
    val rendered = prettyPrint(limit = 240).substringBefore('\n')
    val marker = rendered.indexOf(')', rendered.indexOf("overallLength="))
    return rendered.substring(if (marker < 0) rendered.length else marker + 1).trim()
        .takeIf { it.isNotEmpty() }?.let { "  $it" } ?: ""
}

private fun Asn1Element.childrenOrNull() = when (this) {
    is Asn1Structure -> children
    is Asn1EncapsulatingOctetString -> children
    else -> null
}
