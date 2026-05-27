// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.encoding.internal

import at.asitplus.awesn1.*
import kotlin.experimental.and
import kotlin.jvm.JvmName

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


@InternalAwesn1Api
@Suppress("NOTHING_TO_INLINE")
internal inline fun Source<*>.doParseExactly(nBytes: Long): List<Asn1Element> = doParseExactly(nBytes.toULong())

@InternalAwesn1Api
@JvmName("doParseExactlyULong")
private fun Source<*>.doParseExactly(nBytes: ULong): List<Asn1Element> = mutableListOf<Asn1Element>().also { list ->
    require(nBytes <= Long.MAX_VALUE.toULong()) { "Max number of bytes to read exceeds ${Long.MAX_VALUE}: $nBytes" }
    val boundedSource = BoundedSource(this, nBytes.toLong())
    var nBytesRead: ULong = 0u
    while (nBytesRead < nBytes) {
        val peekTagAndLen = boundedSource.peekTagAndLen()
        require(peekTagAndLen.tagAndLength.length <= (nBytes.toLong() - peekTagAndLen.bytesRead)) {
            "ASN.1 element length for tag ${peekTagAndLen.first.tag} exceeds parent length: ${peekTagAndLen.tagAndLength.length} > ${(nBytes.toLong() - peekTagAndLen.bytesRead)}"
        }
        val numberOfNextBytesRead = peekTagAndLen.second.toULong() + peekTagAndLen.first.length.toULong()
        require(numberOfNextBytesRead <= Long.MAX_VALUE.toULong()) { "Length overflow: $numberOfNextBytesRead" }
        if (nBytesRead + numberOfNextBytesRead > nBytes) break
        boundedSource.skip(peekTagAndLen.second.toLong()) // we only peeked before, so now we need to skip,
                                                                    // since we want to recycle the result below
        val (elem, read) = boundedSource.readAsn1Element(peekTagAndLen.first, peekTagAndLen.second, (nBytes - nBytesRead).toLong())
        list.add(elem)
        nBytesRead += read.toULong()
        require(nBytesRead <= Long.MAX_VALUE.toULong()) { "Length overflow: $nBytesRead" }
    }
    require(nBytesRead == nBytes) { "Indicated length ($nBytes) does not correspond to an ASN.1 element boundary ($nBytesRead)" }
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
    BoundedSource(this, limit).let { boundedSource ->
        mutableListOf<Asn1Element>().let { list ->
            var bytesRead = 0L
            while (!boundedSource.exhausted()) {
                val remainingLimit = limit?.let { it - bytesRead }?.also {
                    require(it > 0) { "ASN.1 element exceeds limit: $bytesRead >= $limit" }
                }
                boundedSource.readAsn1Element(remainingLimit).also { (elem, nBytes) ->
                    bytesRead += nBytes
                    list.add(elem)
                }
            }
            Pair(list, bytesRead)
        }
    }

/**
 * Reads a [TagAndLength] and the number of consumed bytes from the source without consuming it
 */
@InternalAwesn1Api
private fun BoundedSource<*>.peekTagAndLen() = peek().readTagAndLength()

/**
 * Decodes a single [Asn1Element] from this source.
 *
 * @param limit the maximum allowed total number of encoded DER bytes to consume.
 * This limit is enforced before reading or peeking from the underlying source.
 * @return the decoded element and the number of bytes read from the source
 */
@Throws(Asn1Exception::class)
@InternalAwesn1Api
fun Source<*>.readAsn1Element(limit: Long?): Pair<Asn1Element, Long> = runRethrowing {
    BoundedSource(this, limit).let { boundedSource ->
        val (readTagAndLength, bytesRead) = boundedSource.readTagAndLength()
        boundedSource.readAsn1Element(readTagAndLength, bytesRead, limit)
    }
}

/**
 * RAW decoding of an ASN.1 element after tag and length have already been decoded and consumed from the source
 */
@Throws(Asn1Exception::class)
@InternalAwesn1Api
private fun BoundedSource<*>.readAsn1Element(
    tagAndLength: TagAndLength,
    tagAndLengthBytes: Int,
    limit: Long?
): Pair<Asn1Element, Long> =
    runRethrowing {
        val (tag, length) = tagAndLength
        val totalLength = tagAndLengthBytes.toLong() + length
        //fail fast
        limit?.let { require(totalLength <= limit) { "Length of ASN.1 element exceeds limit: $totalLength > $it" } }

        //ASN.1 SEQUENCE
        (if (tag.isSequence()) Asn1Sequence(doParseExactly(length))

        //ASN.1 SET
        else if (tag.isSet()) Asn1Set.fromPresorted(doParseExactly(length))

        //ASN.1 TAGGED (explicitly)
        else if (tag.isExplicitlyTagged) Asn1ExplicitlyTagged(tag.tagValue, doParseExactly(length))

        //ASN.1 OCTET STRING
        else if (tag == Asn1Element.Tag.OCTET_STRING) Asn1OctetString(this, length)

        //IMPLICIT-ly TAGGED ASN.1 CONSTRUCTED; we don't know if it is a SET OF, SET, SEQUENCE,… so we default to sequence semantics
        else if (tag.isConstructed) Asn1CustomStructure(doParseExactly(length), tag.tagValue, tag.tagClass)

        //IMPLICIT-ly TAGGED ASN.1 PRIMITIVE
        else {
            require(length <= Int.MAX_VALUE) { "Cannot read more than ${Int.MAX_VALUE} into a primitive" }
            Asn1Primitive(tag, readByteArray(length.toInt())) as Asn1Element
        }) to totalLength
    }

private fun Asn1Element.Tag.isSet() = this == Asn1Element.Tag.SET
private fun Asn1Element.Tag.isSequence() = (this == Asn1Element.Tag.SEQUENCE)


/**
 * [Asn1Element.Tag] to the decoded length
 */
private typealias TagAndLength = Pair<Asn1Element.Tag, Long>

private val TagAndLength.tag: Asn1Element.Tag get() = first
private val TagAndLength.length: Long get() = second

/**
 * Reads [TagAndLength] and the number of consumed bytes from the source
 */
@InternalAwesn1Api
private fun BoundedSource<*>.readTagAndLength(): Pair<TagAndLength, Int> = runRethrowing {
    if (exhausted()) throw IllegalArgumentException("Can't read TLV, input empty")

    val tag = readAsn1Tag()
    val length = decodeLength()
    require(length.first >= 0L) { "Illegal length: $length" }
    return Pair((tag to length.first), (length.second + tag.encodedTagLength))
}

val Pair<TagAndLength, Int>.tagAndLength: TagAndLength get() = first
val Pair<TagAndLength, Int>.bytesRead: Int get() = second

/**
 * Decodes the `length` of an ASN.1 element (which is preceded by its tag) from the source.
 * @return the decoded length and the number of bytes consumed
 */
@Throws(IllegalArgumentException::class)
@InternalAwesn1Api
private fun BoundedSource<*>.decodeLength(): Pair<Long, Int> =
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
                    if(it <=30UL) throw Asn1Exception("Tag number $it must be encoded in low-tag-number form. Encoded bytes are: ${byteArrayOf(firstByte, *b).toHexString()}")
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
