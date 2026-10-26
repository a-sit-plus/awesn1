// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(at.asitplus.awesn1.InternalAwesn1Api::class)

package at.asitplus.awesn1.serialization.internal

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.internal.*

internal sealed interface DerInput {
    val consumedElements: Int
    fun hasNext(): Boolean
    fun peek(): DerValue?
    fun advance()
    fun finish()
}

internal sealed interface DerValue {
    val tag: Asn1Element.Tag
    val contentLength: Long
    val isPrimitive: Boolean
    val isStructure: Boolean
    fun readPrimitive(): Asn1Primitive
    fun readTree(maxNestingDepth: Int): Asn1Element
    fun children(maxChildren: Int? = null, allowPrimitiveContent: Boolean = false): DerInput
    fun peekFirstPrimitive(expectedTag: Asn1Element.Tag): Asn1Primitive?
    fun requireConsumed()
}

internal class IteratorDerInput(
    private val values: Iterator<DerValue>,
    private val maxChildren: Int? = null,
    private val onFinish: () -> Unit = {},
) : DerInput {
    private var current: DerValue? = null
    private var failed = false
    override var consumedElements = 0
        private set
    init {
        require(maxChildren == null || maxChildren >= 0) { "Child limit must be non-negative" }
    }
    private inline fun <T> operation(block: () -> T): T {
        check(!failed) { "ASN.1 input has failed" }
        return try { block() } catch (failure: Throwable) { failed = true; throw failure }
    }
    override fun hasNext() = operation { current != null || values.hasNext() }
    override fun peek(): DerValue? = operation {
        if (current == null && values.hasNext()) {
            check(maxChildren == null || consumedElements < maxChildren) { "ASN.1 direct-child limit exceeded" }
            current = values.next()
        }
        current
    }
    override fun advance() = operation {
        checkNotNull(current) { "No current ASN.1 value" }.requireConsumed()
        consumedElements++
        current = null
    }
    override fun finish() = operation {
        check(!hasNext()) { "Unread ASN.1 content" }
        onFinish()
    }
}

internal class TreeDerValue(private val element: Asn1Element) : DerValue {
    override val tag get() = element.tag
    override val contentLength get() = element.contentLengthLong
    override val isPrimitive get() = element is Asn1Primitive
    override val isStructure get() = element is Asn1Structure
    private var consumed = false
    override fun readPrimitive(): Asn1Primitive = element.asPrimitive().also { consumed = true }
    override fun readTree(maxNestingDepth: Int): Asn1Element = element.also { consumed = true }
    override fun children(maxChildren: Int?, allowPrimitiveContent: Boolean): DerInput {
        val children = when (element) {
            is Asn1Structure -> element.children
            is Asn1EncapsulatingOctetString -> element.children
            is Asn1Primitive -> {
                check(allowPrimitiveContent) { "Expected ASN.1 structure" }
                val bytes = element.content
                consumed = false
                return sourceDerInput(BoundedSource(bytes.wrapInUnsafeSource(), bytes.size.toLong()), null, maxChildren) {
                    consumed = true
                }
            }
        }
        consumed = false
        return IteratorDerInput(children.asSequence().map(::TreeDerValue).iterator(), maxChildren) { consumed = true }
    }
    override fun peekFirstPrimitive(expectedTag: Asn1Element.Tag): Asn1Primitive? =
        (element as? Asn1Structure)?.children?.firstOrNull()?.let { it as? Asn1Primitive }?.takeIf { it.tag == expectedTag }
    override fun requireConsumed() { check(consumed) { "ASN.1 value was not consumed" } }
}

/** Each container shares the byte counter; only its end and remaining depth differ. No nested source wrappers. */
internal fun sourceDerInput(
    source: BoundedSource<*>,
    remainingDepth: Int?,
    maxChildren: Int? = null,
    contentEnd: Long? = null,
    onFinish: () -> Unit = {},
): DerInput = IteratorDerInput(object : Iterator<DerValue> {
    override fun hasNext(): Boolean {
        if (contentEnd != null) {
            check(source.bytesRead <= contentEnd) { "ASN.1 content boundary exceeded" }
            if (source.bytesRead == contentEnd) return false
            if (source.exhausted()) throw Asn1StructuralException("Truncated ASN.1 content")
            return true
        }
        return !source.exhausted()
    }
    override fun next(): DerValue = SourceDerValue(
        source,
        source.peekAsn1Header((contentEnd ?: source.limit)?.minus(source.bytesRead)),
        remainingDepth,
    )
}, maxChildren, onFinish)

private class SourceDerValue(
    private val source: BoundedSource<*>,
    private val header: Asn1Header,
    private val remainingDepth: Int?,
) : DerValue {
    private val start = source.bytesRead
    private var cached: TreeDerValue? = null
    private var consumed = false
    private var failed = false
    private inline fun <T> operation(block: () -> T): T {
        check(!failed) { "ASN.1 value has failed" }
        return try { block() } catch (failure: Throwable) { failed = true; throw failure }
    }
    private fun requireUnread() {
        check(source.bytesRead == start) { "ASN.1 value was already entered or consumed" }
    }
    private fun requireDescent() {
        check(remainingDepth == null || remainingDepth > 0) { "ASN.1 nesting depth exceeded" }
    }
    override val tag get() = cached?.tag ?: header.tag
    override val contentLength get() = cached?.contentLength ?: header.contentLength
    override val isPrimitive get() = cached?.isPrimitive ?: !tag.isConstructed
    override val isStructure get() = cached?.isStructure ?: tag.isConstructed
    override fun readPrimitive(): Asn1Primitive = operation {
        cached?.readPrimitive() ?: run {
            requireUnread()
            source.readAsn1Primitive(header).also { consumed = true }
        }
    }
    override fun readTree(maxNestingDepth: Int): Asn1Element = operation {
        if (cached == null) {
            requireUnread()
            cached = TreeDerValue(source.readAsn1Element(
                header.totalLength, minOf(remainingDepth ?: maxNestingDepth, maxNestingDepth),
            ).also { check(it.second == header.totalLength) { "ASN.1 element is incomplete" } }.first)
        }
        cached!!.readTree(maxNestingDepth)
    }
    override fun children(maxChildren: Int?, allowPrimitiveContent: Boolean): DerInput = operation {
        cached?.children(maxChildren, allowPrimitiveContent) ?: run {
            requireUnread()
            check(isStructure || allowPrimitiveContent || (tag == Asn1Element.Tag.OCTET_STRING && contentLength > 0)) {
                "Expected ASN.1 structure"
            }
            requireDescent()
            // The header's total length already fits the remaining source budget and parent content.
            val end = start + header.totalLength
            source.skip(header.headerLength.toLong())
            sourceDerInput(source, remainingDepth?.minus(1), maxChildren, end) { consumed = true }
        }
    }
    override fun peekFirstPrimitive(expectedTag: Asn1Element.Tag): Asn1Primitive? = operation {
        if (cached != null) cached!!.peekFirstPrimitive(expectedTag)
        else if (contentLength == 0L) null
        else {
            requireUnread()
            requireDescent()
            val view = source.peek()
            view.skip(header.headerLength.toLong())
            val child = view.peekAsn1Header(contentLength)
            if (child.tag != expectedTag || child.tag.isConstructed) null else view.readAsn1Primitive(child)
        }
    }
    override fun requireConsumed() = operation {
        cached?.let { it.requireConsumed() } ?: check(consumed) { "ASN.1 value was not consumed" }
    }
}
