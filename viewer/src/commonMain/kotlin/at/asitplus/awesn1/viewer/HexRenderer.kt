// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.viewer

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1EncapsulatingOctetString
import at.asitplus.awesn1.Asn1Structure

enum class HexByteKind { TAG, LENGTH, VALUE }

typealias Asn1Path = List<Int>

data class ColoredHexByte(val value: Byte, val kind: HexByteKind, val depth: Int, val path: Asn1Path)
data class GenericAsn1Line(
    val text: String,
    val depth: Int,
    val path: Asn1Path? = null,
    val byteOffset: Int? = null,
    val byteLength: Int? = null,
    val memberName: String? = null,
    val hasPrimitiveContent: Boolean = false,
    val isRoot: Boolean = false,
)

private const val MAX_RENDERED_HEX_BYTES = 64 * 1024

fun coloredHex(element: Asn1Element): Pair<List<ColoredHexByte>, Boolean> = coloredHex(listOf(element))

fun coloredHex(elements: List<Asn1Element>): Pair<List<ColoredHexByte>, Boolean> {
    val totalLength = elements.sumOf(Asn1Element::overallLength)
    val result = ArrayList<ColoredHexByte>(minOf(totalLength, MAX_RENDERED_HEX_BYTES))
    val stack = ArrayDeque<Triple<Asn1Element, Int, Asn1Path>>().apply {
        for (index in elements.indices.reversed()) addLast(Triple(elements[index], 0, listOf(index)))
    }
    while (stack.isNotEmpty() && result.size < MAX_RENDERED_HEX_BYTES) {
        val (current, depth, path) = stack.removeLast()
        current.tag.encodedTag.forEach { result.add(ColoredHexByte(it, HexByteKind.TAG, depth, path)) }
        current.encodedLength.forEach { result.add(ColoredHexByte(it, HexByteKind.LENGTH, depth, path)) }
        val children = current.childrenOrNull()
        if (children == null) {
            val headerSize = current.tag.encodedTag.size + current.encodedLength.size
            current.derEncoded.drop(headerSize).forEach { result.add(ColoredHexByte(it, HexByteKind.VALUE, depth, path)) }
        } else for (index in children.indices.reversed()) stack.addLast(Triple(children[index], depth + 1, path + index))
    }
    // ponytail: cap DOM nodes; use canvas rendering if full multi-megabyte hex output becomes necessary.
    return result.take(MAX_RENDERED_HEX_BYTES) to (totalLength > MAX_RENDERED_HEX_BYTES)
}

fun genericAsn1Lines(
    element: Asn1Element,
    memberNames: Map<Asn1Path, String> = emptyMap(),
    valueNames: Map<Asn1Path, String> = emptyMap(),
): List<GenericAsn1Line> = genericAsn1Lines(listOf(element), memberNames, valueNames)

fun genericAsn1Lines(
    elements: List<Asn1Element>,
    memberNames: Map<Asn1Path, String> = emptyMap(),
    valueNames: Map<Asn1Path, String> = emptyMap(),
): List<GenericAsn1Line> = buildList {
    data class Pending(val element: Asn1Element, val depth: Int, val path: Asn1Path, val offset: Int)
    var rootOffset = 0
    val rootOffsets = elements.map { root -> rootOffset.also { rootOffset += root.overallLength } }
    val stack = ArrayDeque<Pending>().apply {
        for (index in elements.indices.reversed()) addLast(Pending(elements[index], 0, listOf(index), rootOffsets[index]))
    }
    while (stack.isNotEmpty()) {
        val (current, depth, path, offset) = stack.removeLast()
        val isRoot = path.size == 1
        val memberName = memberNames[path].let { name ->
            if (!isRoot || elements.size == 1) name
            else listOfNotNull(name, "(${path.single() + 1}/${elements.size})").joinToString(" ")
        }
        add(GenericAsn1Line(
            current.friendlyHeader(valueNames[path]), depth, path, offset, current.overallLength, memberName,
            current.childrenOrNull() == null, isRoot,
        ))
        current.childrenOrNull()?.let { children ->
            var childOffset = offset + current.tag.encodedTag.size + current.encodedLength.size
            val offsets = children.map { child -> childOffset.also { childOffset += child.overallLength } }
            for (index in children.indices.reversed()) {
                stack.addLast(Pending(children[index], depth + 2, path + index, offsets[index]))
            }
        }
    }
}

private fun Asn1Element.friendlyHeader(valueName: String? = null): String {
    val children = childrenOrNull()
    val summary = when {
        this is Asn1EncapsulatingOctetString ->
            "(${contentLengthLong} byte${if (contentLengthLong == 1L) "" else "s"}, ${children!!.size} elem)"
        children != null -> "(${children.size} elem)"
        else -> valueName ?: primitiveValue()
    }
    return listOf(summary, "tag=$tag, length=$contentLengthLong").filter { it.isNotEmpty() }.joinToString("  ")
}

private fun Asn1Element.primitiveValue(): String {
    val rendered = prettyPrint(limit = 240).substringBefore('\n')
    val marker = rendered.indexOf(')', rendered.indexOf("overallLength="))
    return rendered.substring(if (marker < 0) rendered.length else marker + 1).trim()
}

private fun Asn1Element.childrenOrNull() = when (this) {
    is Asn1Structure -> children
    is Asn1EncapsulatingOctetString -> children
    else -> null
}
