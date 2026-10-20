// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(at.asitplus.awesn1.InternalAwesn1Api::class)

package at.asitplus.awesn1.encoding.internal

import at.asitplus.awesn1.*

/** Shared committed position and failure state. No per-ancestor source wrapper chain. */
internal class Asn1ReadSession(source: Source<*>, limit: Long?, val maxDepth: Int?) {
    val source = BoundedSource(source, limit)
    private var failed = false

    init { maxDepth?.let { require(it >= 0) { "Nesting limit must be non-negative" } } }

    fun <T> operation(block: () -> T): T {
        check(!failed) { "ASN.1 reader session has failed" }
        return try { block() } catch (failure: Throwable) {
            failed = true
            throw failure
        }
    }
}

/**
 * Bounded, partially validated TLV traversal. [finish] checks completion without draining input.
 * Selecting a header leaves the source at the tag; only consuming its handle commits bytes.
 * The synthetic root has depth zero. Entering any element's TLV content, including primitive
 * OCTET content, adds one level; reading a primitive payload adds none. A zero depth limit
 * therefore permits primitive reads but no content descent. Child limits apply only to the
 * direct children of their reader, and any operational failure invalidates the whole session.
 */
@InternalAwesn1Api
class Asn1Reader internal constructor(
    internal val session: Asn1ReadSession,
    internal val end: Long?,
    internal val depth: Int,
    private val maxChildren: Int?,
    private val owner: Asn1ElementReader?,
) {
    constructor(
        source: Source<*>, limit: Long?, maxNestingDepth: Int? = null, maxChildren: Int? = null,
    ) : this(Asn1ReadSession(source, limit, maxNestingDepth), null, 0, maxChildren, null)

    init { maxChildren?.let { require(it >= 0) { "Child limit must be non-negative" } } }

    var elementsRead: Long = 0
        private set
    private var outstanding: Asn1ElementReader? = null
    private var finished = false

    /** Checks the content boundary or root EOF without inspecting the next TLV header. */
    fun hasNext(): Boolean = session.operation {
        check(!finished) { "ASN.1 reader is finished" }
        val position = session.source.bytesRead
        if (end != null && position == end) false
        else {
            check(end == null || position < end) { "ASN.1 content boundary exceeded" }
            val exhausted = session.source.exhausted()
            if (end != null && exhausted) throw Asn1StructuralException("Truncated ASN.1 content")
            !exhausted
        }
    }

    fun next(): Asn1ElementReader = session.operation {
        check(outstanding == null || outstanding!!.completed) { "Previous ASN.1 element is unfinished" }
        check(hasNext()) { "No ASN.1 element remains" }
        if (maxChildren != null && elementsRead >= maxChildren) {
            throw Asn1ParseLimitException("ASN.1 direct-child limit exceeded: $maxChildren")
        }
        val position = session.source.bytesRead
        val remaining = end?.minus(position)
        val header = BoundedSource(session.source, remaining).peek().readAsn1Header()
        val elementEnd = position.plusExact(header.totalLength)
        require(end == null || elementEnd <= end) { "ASN.1 child length exceeds parent length" }
        require(session.source.limit == null || elementEnd <= session.source.limit!!) {
            "Length of ASN.1 element exceeds limit"
        }
        Asn1ElementReader(this, header, elementEnd).also {
            outstanding = it
            elementsRead++
        }
    }

    fun finish(): Unit = session.operation {
        check(!finished) { "ASN.1 reader is finished" }
        check(outstanding == null || outstanding!!.completed) { "Unfinished ASN.1 element" }
        check(!hasNext()) { "Unread ASN.1 content or trailing bytes" }
        finished = true
        owner?.complete()
    }
}

/** A single selected TLV. Header peeks are temporary and never retained across committed reads. */
@InternalAwesn1Api
class Asn1ElementReader internal constructor(
    private val parent: Asn1Reader,
    val header: Asn1TlvHeader,
    private val end: Long,
) {
    private val session get() = parent.session
    internal var completed = false
        private set
    private var entered = false

    private fun requireUnconsumed() {
        check(!completed && !entered) { "ASN.1 element already consumed or entered" }
    }

    internal fun complete() {
        check(session.source.bytesRead == end) { "ASN.1 element is incomplete" }
        completed = true
    }

    fun readPrimitive(): Asn1Primitive = session.operation {
        requireUnconsumed()
        require(!header.tag.isConstructed) { "Expected primitive ASN.1 wire tag" }
        require(header.contentLength <= Int.MAX_VALUE) { "Primitive exceeds ByteArray size" }
        session.source.skip(header.headerLength.toLong())
        Asn1Primitive(header.tag, session.source.readByteArray(header.contentLength.toInt())).also { complete() }
    }

    /** Interprets content as TLVs even for primitive tags; the caller authorizes that interpretation. */
    fun enterContent(maxChildren: Int? = null): Asn1Reader = session.operation {
        requireUnconsumed()
        require(maxChildren == null || maxChildren >= 0) { "Child limit must be non-negative" }
        if (session.maxDepth != null && parent.depth >= session.maxDepth!!) {
            throw Asn1ParseLimitException("ASN.1 nesting depth exceeds ${session.maxDepth}")
        }
        session.source.skip(header.headerLength.toLong())
        entered = true
        Asn1Reader(session, end, parent.depth + 1, maxChildren, this)
    }

    /** Uses the existing tree parser within the smaller session/per-call remaining depth allowance. */
    fun readTree(maxNestingDepth: Int? = null): Asn1Element = session.operation {
        requireUnconsumed()
        require(maxNestingDepth == null || maxNestingDepth >= 0) { "Nesting limit must be non-negative" }
        val remaining = session.maxDepth?.minus(parent.depth)
        val allowed = if (remaining == null) maxNestingDepth
            else maxNestingDepth?.let { minOf(it, remaining) } ?: remaining
        session.source.readAsn1Element(header.totalLength, allowed).first.also { complete() }
    }

    /** Narrow discriminator lookahead: no committed bytes, child count, or subsequent child is inspected. */
    fun peekFirstPrimitive(expectedTag: Asn1Element.Tag): Asn1Primitive? = session.operation {
        requireUnconsumed()
        if (header.contentLength == 0L) return@operation null
        val peek = session.source.peek()
        peek.skip(header.headerLength.toLong())
        val child = Asn1Reader(peek, header.contentLength, session.maxDepth?.minus(parent.depth + 1)).next()
        if (child.header.tag != expectedTag || child.header.tag.isConstructed) null else child.readPrimitive()
    }
}
