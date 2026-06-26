// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.encoding.internal

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.toAsn1VarInt
import kotlin.experimental.and

//start defence in depth helpers; if any of these is ever reached, hardware is either beefy or sensible limits were omitted.

/** Conservative maximum collection size — the largest array length addressable on the JVM. */
internal const val MAX_COLLECTION_SIZE = Int.MAX_VALUE - 8

@Suppress("NOTHING_TO_INLINE")
private inline fun <E> MutableList<E>.addGuarded(element: E) {
    if (size >= MAX_COLLECTION_SIZE)
        throw Asn1Exception("ASN.1 input exceeds the maximum addressable element/nesting count ($MAX_COLLECTION_SIZE)")
    add(element)
}

@Suppress("NOTHING_TO_INLINE")
private inline fun <E> MutableList<E>.addAllGuarded(elements: Collection<E>) {
    if (size.toLong() + elements.size > MAX_COLLECTION_SIZE)
        throw Asn1Exception("ASN.1 input exceeds the maximum addressable element/nesting count ($MAX_COLLECTION_SIZE)")
    addAll(elements)
}

//end defence in depth helpers

/**
 * Parses the provided [source] into a single [Asn1Element].
 *
 * @param limit the maximum allowed total number of encoded DER bytes to consume.
 * This limit is enforced before reading or peeking from the underlying source.
 */
@InternalAwesn1Api
@Throws(Asn1Exception::class)
fun Asn1Element.Companion.parse(source: Source<*>, limit: Long?): Asn1Element =
    parseFirst(source, limit).also {
        if (!source.exhausted()) throw Asn1StructuralException("Trailing bytes found after the first ASN.1 element")
    }.first


/**
 * Parses all ASN.1 elements from [source].
 *
 * @param limit the maximum allowed total number of encoded DER bytes to consume.
 * This limit is enforced before reading or peeking from the underlying source.
 */
@InternalAwesn1Api
@Throws(Asn1Exception::class)
fun Asn1Element.Companion.parseAll(source: Source<*>, limit: Long?): List<Asn1Element> =
    source.readFullyToAsn1Elements(limit).first

/**
 * Parses the first ASN.1 element from [source].
 *
 * @param limit the maximum allowed total number of encoded DER bytes to consume.
 * This limit is enforced before reading or peeking from the underlying source.
 */
@InternalAwesn1Api
@Throws(Asn1Exception::class)
fun Asn1Element.Companion.parseFirst(source: Source<*>, limit: Long?): Pair<Asn1Element, Long> =
    source.readAsn1Element(limit)


/**
 * "Stack" Frame for iterative decoding ont eh heap.
 */
@InternalAwesn1Api
private class Frame(
    val tag: Asn1Element.Tag,
    val contentLength: Long,
    val numHeaderBytes: Int,
) {
    var bytesConsumed: Long = 0
    val children = mutableListOf<Asn1Element>()
    val octetIndices = mutableListOf<Int>()

    // plusExact: a crafted contentLength near Long.MAX_VALUE must not silently wrap (it would corrupt the
    // bytesConsumed/topBytesRead accounting that enforces the byte limit). Overflow -> Asn1Exception.
    val totalLength: Long get() = contentLength.plusExact(numHeaderBytes.toLong())

    /* Mirrors the constructed-element classification of the former recursive parser. */
    fun buildStructure(): Asn1Structure = when {
        tag.isSequence() -> Asn1Sequence.adopting(children)
        tag.isSet() -> Asn1Set.fromPresorted(children)
        tag.isExplicitlyTagged -> Asn1ExplicitlyTagged(tag.tagValue, children)
        else -> Asn1CustomStructure(tag, children, sortChildren = false, shouldBeSorted = false)
    }
}

/**
 * A raw OCTET STRING discovered during parsing, together with the means to replace it in place with its
 * encapsulating counterpart once (and if) its content is decoded. [raw] is the node to peel; [replaceWith] swaps
 * the node in its containing structure / encapsulating octet string / root list.
 */
@InternalAwesn1Api
private class OctetSlot(val raw: Asn1OctetString, val replaceWith: (Asn1EncapsulatingOctetString) -> Unit)

/**
 * Result of one structural parse pass: the parsed [roots], the number of bytes consumed ([bytesRead]), and every
 * raw OCTET STRING found along the way as a ready-to-use [OctetSlot]. Requires one pass to decapsulate octet strings.
 */
@InternalAwesn1Api
private class ParseResult(
    val roots: MutableList<Asn1Element>,
    val bytesRead: Long,
    val octets: MutableList<OctetSlot>,
)

/**
 * Iteratively parses DER TLV input, using an explicit stack ([ArrayDeque] of [Frame]s in place of the former
 * `readAsn1Element`/`doParseExactly` recursion, s.t structural nesting depth no longer grows the call
 * stack. This is important because realistic expectations wrt. stack size differ per target.
 * This was realistically irrelevant for well-formed data, but an easy DoS entry point using deliberately crafted, deeply nested data.
 * Now it's safe anyhow.
 *
 * OCTET STRING content is left raw here; encapsulated content is decoded iteratively afterwards by
 * [parseOctetStrings]. The raw OCTET STRINGs found are reported via [ParseResult] so that decoding does not have
 * to re-walk the tree.
 *
 * @param limit the maximum total number of encoded DER bytes to consume.
 * @param single if `true`, stops after the first top-level element (used by [readAsn1Element]).
 */
/*
 * NOTE on why this stays hand-rolled: a single conflated rewrite using [kotlin.DeepRecursiveFunction] (both the
 * structural walk and inline OCTET STRING decapsulation, soft-failing via try/catch) was benchmarked ~28–36% slower on real-world certificate data.
 */
//called only in three other functions with no other body, so we inline here
@Suppress("NOTHING_TO_INLINE")
@InternalAwesn1Api
private inline fun Source<*>.doParse(limit: Long?, single: Boolean): ParseResult =
    runRethrowing {
        val rootSrc = BoundedSource(this, limit)
        val roots = mutableListOf<Asn1Element>()
        val stack = ArrayDeque<Frame>()
        var topBytesRead = 0L
        val octets = mutableListOf<OctetSlot>()

        while (true) {
            // close every frame whose declared content has been fully consumed, crediting it to its parent
            while (stack.isNotEmpty() && stack.last().bytesConsumed == stack.last().contentLength) {
                val frame = stack.removeLast()
                val built = frame.buildStructure()
                val frameLength= frame.totalLength
                val octetIndices = frame.octetIndices //frame now free for GC

                // a structure copies its children, so translate this frame's discovery-time octet markers into
                // stable slots against the built structure (order is preserved, so recorded indices line up)
                octetIndices.forEach { i ->
                    octets.addGuarded(OctetSlot(built.children[i] as Asn1OctetString) { built.replaceChild(i, it) })
                }
                val parent = stack.lastOrNull()
                if (parent == null) {
                    roots.addGuarded(built)
                    topBytesRead += frameLength
                } else {
                    parent.children.addGuarded(built)
                    // credit the parent for the whole child element (header + content), now that it is complete
                    parent.bytesConsumed += frameLength
                }
            }

            stack.lastOrNull()?.also { parent ->
                // bound only the header peek to the parent's remaining content, so a malformed header cannot read
                // past the boundary; this wraps the single root source (constant depth), not the parent frame
                val remaining = parent.contentLength - parent.bytesConsumed
                val (tagAndLength, headerBytes) = BoundedSource(rootSrc, remaining).peek().readTagAndLength()
                val (tag, length) = tagAndLength
                require(length <= parent.contentLength - headerBytes) {
                    "ASN.1 element length for tag $tag exceeds parent length: $length > ${parent.contentLength - headerBytes}"
                }
                val childTotal = length.plusExact(headerBytes.toLong())
                if (parent.bytesConsumed + childTotal > parent.contentLength) {
                    throw Asn1StructuralException(
                        "Indicated length (${parent.contentLength}) does not correspond to an ASN.1 element boundary (${parent.bytesConsumed})"
                    )
                }
                rootSrc.skip(headerBytes.toLong())
                stack.pushOrPrimitive(tag, length, rootSrc, headerBytes)?.let {
                    parent.children.addGuarded(it)
                    // a leaf consumes header + content immediately; constructed children are credited on close above
                    parent.bytesConsumed += childTotal
                    if (it is Asn1OctetString) parent.octetIndices.addGuarded(parent.children.lastIndex)
                }
            } ?: run {
                if (single && roots.isNotEmpty()) break //can only ever land here after parsing a single element
                if (rootSrc.exhausted()) break //done anywys

                val (tagAndLength, headerBytes) = rootSrc.readTagAndLength()
                val (tag, length) = tagAndLength
                val totalLength = length.plusExact(headerBytes.toLong())
                limit?.let {
                    require(totalLength <= it - topBytesRead) {
                        "Length of ASN.1 element exceeds limit: $totalLength > ${it - topBytesRead}"
                    }
                }
                stack.pushOrPrimitive(tag, length, rootSrc, headerBytes)?.let {
                    roots.addGuarded(it)
                    topBytesRead += totalLength
                    // root octets are homed directly to the roots list; the node that later wraps roots adopts it
                    if (it is Asn1OctetString) {
                        val index = roots.lastIndex
                        octets.addGuarded(OctetSlot(it) { node -> roots[index] = node })
                    }
                }
            }
        }

        ParseResult(roots, topBytesRead, octets)
    }

// Builds a leaf element from an already-decoded tag/length (reading its content from [src]), or pushes
// a frame for a constructed element and returns `null`. This is where we previously recursed.
@OptIn(InternalAwesn1Api::class)
private fun ArrayDeque<Frame>.pushOrPrimitive(
    tag: Asn1Element.Tag,
    length: Long,
    src: Source<*>,
    numHeaderBytes: Int
): Asn1Element? = when {
    //SET, SEQUENCE, EXPLICITLY-TAGGED, Asn1CustomStructure
    tag.isConstructed -> {
        this.addGuarded(Frame(tag, length, numHeaderBytes)) // ArrayDeque is a MutableList; appends to the end
        null
    }

    tag == Asn1Element.Tag.OCTET_STRING -> {
        require(length <= Int.MAX_VALUE) { "Cannot read more than ${Int.MAX_VALUE} into an OCTET STRING" }
        //leave OCTET STRING content raw here; encapsulated content is decoded iteratively afterwards (see drainEncapsulatedOctetStrings)
        Asn1OctetString.nonEncapsulating(src.readByteArray(length.toInt()))
    }

    else -> {
        require(length <= Int.MAX_VALUE) { "Cannot read more than ${Int.MAX_VALUE} into a primitive" }
        Asn1Primitive(tag, src.readByteArray(length.toInt()))
    }
}


/**
 * Reads all parsable ASN.1 elements from this source.
 *
 * @param limit the maximum allowed total number of encoded DER bytes to consume.
 * This limit is enforced before reading or peeking from the underlying source.
 * @throws Asn1Exception on error if any illegal element or any trailing bytes are encountered
 */
@Throws(Asn1Exception::class)
@InternalAwesn1Api
fun Source<*>.readFullyToAsn1Elements(limit: Long?): Pair<List<Asn1Element>, Long> =
    doParse(limit, single = false).let { ArrayDeque(it.octets).parseOctetStrings(); it.roots to it.bytesRead }

/**
 * Decodes a single [Asn1Element] from this source.
 *
 * @param limit the maximum allowed total number of encoded DER bytes to consume.
 * This limit is enforced before reading or peeking from the underlying source.
 * @return the decoded element and the number of bytes read from the source
 */
@Throws(Asn1Exception::class)
@InternalAwesn1Api
fun Source<*>.readAsn1Element(limit: Long?): Pair<Asn1Element, Long> =
    doParse(limit, single = true).let {
        // a single element was requested; empty input cannot satisfy that, so fail with an Asn1Exception
        // (rather than letting roots.first() throw a raw NoSuchElementException)
        if (it.roots.isEmpty()) throw Asn1Exception("Cannot decode an ASN.1 element from empty input")
        ArrayDeque(it.octets).parseOctetStrings()
        it.roots.first() to it.bytesRead
    }

/**
 * Decodes a standalone [Asn1OctetString] (e.g. constructed from raw bytes): iteratively peels it and any
 * OCTET STRINGs its content reveals, returning the encapsulating node on success or the raw octet string itself.
 */
@InternalAwesn1Api
internal fun Asn1OctetString.decapsulateOrSelf(): Asn1OctetString {
    var holder = this
    ArrayDeque<OctetSlot>().apply { addLast(OctetSlot(this@decapsulateOrSelf) { holder = it }) }.parseOctetStrings()
    return holder
}

/**
 * In-place, iterative counterpart to the former recursive OCTET STRING decoding. Drains a work-list of raw
 * OCTET STRINGs ([OctetSlot]s) (discovered during parsing — see [doParse]), replacing each whose content is
 * valid DER with an [Asn1EncapsulatingOctetString] and leaving the rest raw. Each peel decodes exactly one layer
 * via the iterative [doParse]. Must run before the tree escapes. See `equals`/`hashCode` caveat in [Asn1Structure.replaceChild].
 */
@InternalAwesn1Api
private fun ArrayDeque<OctetSlot>.parseOctetStrings() {
    while (isNotEmpty()) {
        val slot = removeFirst()
        val content = slot.raw.content
        catchingUnwrapped {
            val layer = content.wrapInUnsafeSource().doParse(content.size.toLong(), single = false)
            require(layer.roots.isNotEmpty())
            addAllGuarded(layer.octets)
            Asn1EncapsulatingOctetString.decapsulated(layer.roots)
        }.getOrNull()?.let { slot.replaceWith(it) }
    }
}

private fun Asn1Element.Tag.isSet() = this == Asn1Element.Tag.SET
private fun Asn1Element.Tag.isSequence() = (this == Asn1Element.Tag.SEQUENCE)


/**
 * [Asn1Element.Tag] to the decoded length
 */
private typealias TagAndLength = Pair<Asn1Element.Tag, Long>

/**
 * Reads [TagAndLength] and the number of consumed bytes from the source
 */
@InternalAwesn1Api
private fun Source<*>.readTagAndLength(): Pair<TagAndLength, Int> = runRethrowing {
    if (exhausted()) throw IllegalArgumentException("Can't read TLV, input empty")

    val tag = readAsn1Tag()
    val length = decodeLength()
    require(length.first >= 0L) { "Illegal length: $length" }
    return Pair((tag to length.first), (length.second + tag.encodedTagLength))
}

/**
 * Decodes the `length` of an ASN.1 element (which is preceded by its tag) from the source.
 * @return the decoded length and the number of bytes consumed
 */
@Throws(IllegalArgumentException::class)
@InternalAwesn1Api
private fun Source<*>.decodeLength(): Pair<Long, Int> =
    readByte().let { firstByte ->
        if (firstByte.isBerShortForm()) {
            Pair(firstByte.toUByte().toLong(), 1)
        } else { // its BER long form!
            val numberOfLengthOctets = (firstByte byteMask 0x7F).toInt()
            if (numberOfLengthOctets == 0) throw Asn1Exception("Illegal DER length encoding; indefinite length is not allowed")
            if (numberOfLengthOctets > 8) throw Asn1Exception("Unsupported length >2^8 (was: $numberOfLengthOctets length bytes)")
            val length = (0 until numberOfLengthOctets).fold(0uL) { acc, index ->
                require(!exhausted()) { "Can't decode length. End of input reached before all length bytes were read" }
                val thisByte = readUByte().also {
                    if ((index == 0) && (it == 0u.toUByte())) {
                        throw Asn1Exception("Illegal DER length encoding; long form length with leading zeros")
                    }
                }.toULong()
                acc or (thisByte shl Byte.SIZE_BITS * (numberOfLengthOctets - index - 1))
            }
            if (length < 128uL) throw Asn1Exception("Illegal DER length encoding; length $length < 128 using long form")
            if (length > Long.MAX_VALUE.toULong()) throw Asn1Exception("Unsupported length >Long.MAX_VALUE: $length")
            Pair(length.toLong(), 1 + numberOfLengthOctets)
        }
    }

private fun Byte.isBerShortForm() = this byteMask 0x80 == 0x00.toUByte()

internal infix fun Byte.byteMask(mask: Int) = (this and mask.toUInt().toByte()).toUByte()


@InternalAwesn1Api
fun Source<*>.readAsn1Tag(): Asn1Element.Tag =
    readByte().let { firstByte ->
        (firstByte byteMask 0x1F).let { tagNumber ->
            if (tagNumber <= 30U) Asn1Element.Tag(tagNumber.toULong(), byteArrayOf(firstByte))
            else decodeAsn1VarULong().let { (l, b) ->
                Asn1Element.Tag(l.also {
                    if (it <= 30UL) throw Asn1Exception(
                        "Tag number $it must be encoded in low-tag-number form. Encoded bytes are: ${
                            byteArrayOf(firstByte, *b).toHexString()
                        }"
                    )
                    it.toAsn1VarInt().let { canonical ->
                        if (!canonical.contentEquals(b)) throw Asn1Exception(
                            "Tag number $l is not minimally encoded. Encoded bytes are: ${
                                byteArrayOf(firstByte, *b).toHexString()
                            }; canonical tag-number bytes are: ${canonical.toHexString()}"
                        )
                    }
                }, byteArrayOf(firstByte, *b))
            }
        }
    }

/**
 * Decodes [src] as DER using this [Asn1Decodable].
 *
 * @param limit the maximum allowed total number of encoded DER bytes to consume.
 * This limit is enforced before reading or peeking from the underlying source.
 */
@InternalAwesn1Api
@Throws(Asn1Exception::class)
fun <A : Asn1Element, T : Asn1Encodable<A>> Asn1Decodable<A, T>.decodeFromDer(
    src: Source<*>,
    limit: Long?,
    assertTag: Asn1Element.Tag? = null
): T =
    @Suppress("UNCHECKED_CAST")
    decodeFromTlv(Asn1Element.parse(src, limit) as A, assertTag)
