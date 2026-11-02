// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(at.asitplus.awesn1.InternalAwesn1Api::class)

package at.asitplus.awesn1.serialization.internal

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.internal.*

/**
 * One-shot poison: after any failure the state machine's position is unknowable, so every later operation fails
 * fast. Carries the originating failure along so the poison message names the real problem.
 */
internal class FailedState(failure: Throwable, operation: String) : IllegalStateException(
    "ASN.1 " + operation + " is unavailable after a previous failure: " + failure.message, failure,
)

internal class FailOnce {
    // internal (not private) so the state machines in this file can share the inline guard
    internal var failure: Throwable? = null
    internal inline fun <T> operation(name: String, block: () -> T): T {
        failure?.let { throw FailedState(it, name) }
        try {
            return block()
        } catch (t: Throwable) {
            if (failure == null) failure = t
            throw t
        }
    }
}

internal sealed interface DerValue {
    val tag: Asn1Element.Tag
    val contentLength: Long
    val isPrimitive: Boolean
    fun readPrimitive(): Asn1Primitive
    fun readTree(maxNestingDepth: Int): Asn1Element
    fun children(maxChildren: Int? = null, allowPrimitiveContent: Boolean = false): DerInput
    fun peekFirstPrimitive(expectedTag: Asn1Element.Tag): Asn1Primitive?
    fun requireConsumed()

    class TreeBacked(private val element: Asn1Element) : DerValue {
        override val tag get() = element.tag
        override val contentLength get() = element.contentLengthLong
        override val isPrimitive get() = element is Asn1Primitive
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
                    return BoundedSource(bytes.wrapInUnsafeSource(), bytes.size.toLong()).wrapInDerInput(null, maxChildren) {
                        consumed = true
                    }
                }
            }
            consumed = false
            return DerInput(children.asSequence().map(::TreeBacked).iterator(), maxChildren) { consumed = true }
        }
        override fun peekFirstPrimitive(expectedTag: Asn1Element.Tag): Asn1Primitive? =
            (element as? Asn1Structure)?.children?.firstOrNull()?.let { it as? Asn1Primitive }?.takeIf { it.tag == expectedTag }
        override fun requireConsumed() { check(consumed) { "ASN.1 value was not consumed" } }
    }

    class SourceBacked(
        private val source: BoundedSource<*>,
        private val header: Asn1Header,
        private val remainingDepth: Int?,
    ) : DerValue {
        private val start = source.bytesRead
        private var cached: TreeBacked? = null
        private var consumed = false
        private val failed = FailOnce()
        private fun requireUnread() {
            check(source.bytesRead == start) { "ASN.1 value was already entered or consumed" }
        }
        private fun requireDescent() {
            check(remainingDepth == null || remainingDepth > 0) { "ASN.1 nesting depth exceeded" }
        }
        override val tag get() = header.tag
        override val contentLength get() = header.contentLength
        override val isPrimitive get() = !tag.isConstructed
        override fun readPrimitive(): Asn1Primitive = failed.operation("value") {
            cached?.readPrimitive() ?: run {
                requireUnread()
                source.readAsn1Primitive(header).also { consumed = true }
            }
        }
        override fun readTree(maxNestingDepth: Int): Asn1Element = failed.operation("value tree") {
            if (cached == null) {
                requireUnread()
                cached = TreeBacked(source.readAsn1Element(
                    header.totalLength, minOf(remainingDepth ?: maxNestingDepth, maxNestingDepth),
                ).also { check(it.second == header.totalLength) { "ASN.1 element is incomplete" } }.first)
            }
            cached!!.readTree(maxNestingDepth)
        }
        override fun children(maxChildren: Int?, allowPrimitiveContent: Boolean): DerInput = failed.operation("value children") {
            cached?.children(maxChildren, allowPrimitiveContent) ?: run {
                requireUnread()
                check(!isPrimitive || allowPrimitiveContent || (tag == Asn1Element.Tag.OCTET_STRING && contentLength > 0)) {
                    "Expected ASN.1 structure"
                }
                requireDescent()
                // The header's total length already fits the remaining source budget and parent content.
                val end = start + header.totalLength
                source.skip(header.headerLength.toLong())
                source.wrapInDerInput(remainingDepth?.minus(1), maxChildren, end) { consumed = true }
            }
        }
        override fun peekFirstPrimitive(expectedTag: Asn1Element.Tag): Asn1Primitive? = failed.operation("value peek") {
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
        override fun requireConsumed() = failed.operation("value consume") {
            cached?.let { it.requireConsumed() } ?: check(consumed) { "ASN.1 value was not consumed" }
        }
    }
}

internal class DerInput(
    private val values: Iterator<DerValue>,
    private val maxChildren: Int? = null,
    private val onFinish: () -> Unit = {},
) {
    private var current: DerValue? = null
    private val failed = FailOnce()
    private var consumedElements = 0
    init {
        require(maxChildren == null || maxChildren >= 0) { "Child limit must be non-negative" }
    }
    fun hasNext() = failed.operation("input") { current != null || values.hasNext() }
    fun peek(): DerValue? = failed.operation("input peek") {
        if (current == null && values.hasNext()) {
            check(maxChildren == null || consumedElements < maxChildren) { "ASN.1 direct-child limit exceeded" }
            current = values.next()
        }
        current
    }
    fun advance() = failed.operation("input advance") {
        checkNotNull(current) { "No current ASN.1 value" }.requireConsumed()
        consumedElements++
        current = null
    }
    fun finish() = failed.operation("input finish") {
        check(!hasNext()) { "Unread ASN.1 content" }
        onFinish()
    }
}

/** Each container shares the byte counter; only its end and remaining depth differ. No nested source wrappers. */
internal fun BoundedSource<*>.wrapInDerInput(
    remainingDepth: Int?,
    maxChildren: Int? = null,
    contentEnd: Long? = null,
    onFinish: () -> Unit = {},
): DerInput = DerInput(object : Iterator<DerValue> {
    override fun hasNext(): Boolean {
        if (contentEnd != null) {
            check(bytesRead <= contentEnd) { "ASN.1 content boundary exceeded" }
            if (bytesRead == contentEnd) return false
            if (exhausted()) throw Asn1StructuralException("Truncated ASN.1 content")
            return true
        }
        return !exhausted()
    }
    override fun next(): DerValue = DerValue.SourceBacked(
        this@wrapInDerInput,
        peekAsn1Header((contentEnd ?: limit)?.minus(bytesRead)),
        remainingDepth,
    )
}, maxChildren, onFinish)
