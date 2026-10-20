// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(at.asitplus.awesn1.InternalAwesn1Api::class)

package at.asitplus.awesn1.serialization.internal

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.internal.*
import at.asitplus.awesn1.encoding.parseAll

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
    override var consumedElements = 0
        private set
    override fun hasNext() = current != null || values.hasNext()
    override fun peek(): DerValue? {
        if (current == null && values.hasNext()) {
            check(maxChildren == null || consumedElements < maxChildren) { "ASN.1 direct-child limit exceeded" }
            current = values.next()
        }
        return current
    }
    override fun advance() {
        checkNotNull(current) { "No current ASN.1 value" }.requireConsumed()
        consumedElements++
        current = null
    }
    override fun finish() {
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
                Asn1Element.parseAll(element.content)
            }
        }
        consumed = false
        return IteratorDerInput(children.asSequence().map(::TreeDerValue).iterator(), maxChildren) { consumed = true }
    }
    override fun peekFirstPrimitive(expectedTag: Asn1Element.Tag): Asn1Primitive? =
        (element as? Asn1Structure)?.children?.firstOrNull()?.let { it as? Asn1Primitive }?.takeIf { it.tag == expectedTag }
    override fun requireConsumed() { check(consumed) { "ASN.1 value was not consumed" } }
}

internal class SourceDerInput(private val reader: Asn1Reader, private val onFinish: () -> Unit = {}) : DerInput {
    private var current: DerValue? = null
    override var consumedElements = 0
        private set
    override fun hasNext() = current != null || reader.hasNext()
    override fun peek(): DerValue? {
        if (current == null && reader.hasNext()) current = SourceDerValue(reader.next())
        return current
    }
    override fun advance() {
        checkNotNull(current) { "No current ASN.1 value" }.requireConsumed()
        consumedElements++
        current = null
    }
    override fun finish() {
        check(current == null) { "Unread ASN.1 value" }
        reader.finish()
        onFinish()
    }
}

internal class SourceDerValue(private val element: Asn1ElementReader) : DerValue {
    private var cached: TreeDerValue? = null
    private var entered = false
    private var consumed = false
    override val tag get() = cached?.tag ?: element.header.tag
    override val contentLength get() = cached?.contentLength ?: element.header.contentLength
    override val isPrimitive get() = cached?.isPrimitive ?: !tag.isConstructed
    override val isStructure get() = cached?.isStructure ?: tag.isConstructed
    override fun readPrimitive(): Asn1Primitive {
        cached?.let { return it.readPrimitive() }
        check(!entered && !consumed) { "ASN.1 value already consumed" }
        return element.readPrimitive().also { consumed = true }
    }
    override fun readTree(maxNestingDepth: Int): Asn1Element {
        if (cached == null) {
            check(!entered && !consumed) { "Cannot materialize partially consumed ASN.1 value" }
            cached = TreeDerValue(element.readTree(maxNestingDepth))
        }
        return cached!!.readTree(maxNestingDepth)
    }
    override fun children(maxChildren: Int?, allowPrimitiveContent: Boolean): DerInput {
        cached?.let { return it.children(maxChildren, allowPrimitiveContent) }
        check(!entered && !consumed) { "ASN.1 value already consumed" }
        check(isStructure || allowPrimitiveContent || (tag == Asn1Element.Tag.OCTET_STRING && contentLength > 0)) {
            "Expected ASN.1 structure"
        }
        entered = true
        return SourceDerInput(element.enterContent(maxChildren)) { consumed = true }
    }
    override fun peekFirstPrimitive(expectedTag: Asn1Element.Tag): Asn1Primitive? =
        cached?.peekFirstPrimitive(expectedTag) ?: if (cached == null) element.peekFirstPrimitive(expectedTag) else null
    override fun requireConsumed() {
        cached?.let { it.requireConsumed(); return }
        check(consumed) { "ASN.1 value was not consumed" }
    }
}
