// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(at.asitplus.awesn1.InternalAwesn1Api::class)

package at.asitplus.awesn1.io

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Encodable
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.MAX_RENDER_CHARS
import at.asitplus.awesn1.encoding.KxIoSink
import at.asitplus.awesn1.encoding.KxIoSource
import at.asitplus.awesn1.encoding.internal.*

/**
 * Parses an ASN.1 element from the given source with the specified size limit.
 *
 * @param source The data source from which the ASN.1 element will be read.
 * @param limit The maximum allowed total number of encoded DER bytes to consume.
 * This limit is enforced before reading or peeking from the underlying source.
 * @return The parsed ASN.1 element.
 * @throws Asn1Exception if the input does not parse or if it exceeds the specified limit.
 * This includes length encoding indicating a length greater than [limit],
 * even if this is malformed and exceeds the number of bytes left in the [source].
 */
@Throws(Asn1Exception::class)
fun Asn1Element.Companion.parse(source: kotlinx.io.Source, limit: Long): Asn1Element =
    parse(KxIoSource(source) as Source<*>, limit)

/**
 * Parses all ASN.1 elements from the given source within the specified limit.
 *
 * @param source The input source from which the ASN.1 elements will be parsed.
 * @param limit The maximum allowed total number of encoded DER bytes to consume.
 * This limit is enforced before reading or peeking from the underlying source.
 * @return A list of parsed ASN.1 elements.
 * @throws Asn1Exception if the input does not parse or if it exceeds the specified limit.
 * This includes length encoding indicating a length greater than [limit],
 * even if this is malformed and exceeds the number of bytes left in the [source].
 */
@Throws(Asn1Exception::class)
fun Asn1Element.Companion.parseAll(source: kotlinx.io.Source, limit: Long): List<Asn1Element> =
    parseAll(KxIoSource(source) as Source<*>,limit)

/**
 * Parses the first ASN.1 element from the given source within the specified limit.
 *
 * @param source The input source from which the ASN.1 element will be read.
 * @param limit The maximum allowed total number of encoded DER bytes to consume.
 * This limit is enforced before reading or peeking from the underlying source.
 * @return A pair containing the parsed ASN.1 element and the total number of bytes consumed.
 * @throws Asn1Exception if the input does not parse or if it exceeds the specified limit.
 * This includes length encoding indicating a length greater than [limit],
 * even if this is malformed and exceeds the number of bytes left in the [source].
 */
@Throws(Asn1Exception::class)
fun Asn1Element.Companion.parseFirst(source: kotlinx.io.Source, limit: Long): Pair<Asn1Element, Long> =
    parseFirst(KxIoSource(source) as Source<*>, limit)

/**
 * Reads an ASN.1 element from the source up to the specified byte limit.
 *
 * @param limit The maximum allowed total number of encoded DER bytes to consume.
 * This limit is enforced before reading or peeking from the underlying source.
 * @return A pair consisting of the parsed ASN.1 element and the number of bytes consumed.
 * @throws Asn1Exception if the input does not parse or if it exceeds the specified limit.
 * This includes length encoding indicating a length greater than [limit],
 * even if this is malformed and exceeds the number of bytes left in the [source].
 */
@Throws(Asn1Exception::class)
fun kotlinx.io.Source.readAsn1Element(limit: Long): Pair<Asn1Element, Long> =
    KxIoSource(this).readAsn1Element(limit)

/**
 * Reads all available data from the source up to the specified limit and parses it into a list
 * of ASN.1 elements along with the total number of bytes read.
 *
 * @param limit The maximum allowed total number of encoded DER bytes to consume.
 * This limit is enforced before reading or peeking from the underlying source.
 * @return A pair containing a list of parsed ASN.1 elements and the total number of bytes read.
 * @throws Asn1Exception if the input does not parse or if it exceeds the specified limit.
 * This includes length encoding indicating a length greater than [limit],
 * even if this is malformed and exceeds the number of bytes left in the [source].
 */
@Throws(Asn1Exception::class)
fun kotlinx.io.Source.readFullyToAsn1Elements(limit: Long): Pair<List<Asn1Element>, Long> =
    KxIoSource(this).readFullyToAsn1Elements(limit)

fun Asn1Encodable<*>.encodeToDer(sink: kotlinx.io.Sink) {
    encodeToDer(KxIoSink(sink) as Sink)
}

fun Asn1Element.encodeToDer(sink: kotlinx.io.Sink) {
    encodeTo(KxIoSink(sink) as Sink)
}

/**
 * Writes the compact (`toString`) rendering of this element as UTF-8 into [sink], truncating after [limit] characters
 * (with a marker). Streaming to a sink lets you produce renderings larger than the in-memory [Asn1Element.toString];
 * pass a larger [limit] to render more.
 */
fun Asn1Element.toString(sink: kotlinx.io.Sink, limit: Long = MAX_RENDER_CHARS) {
    renderTo(KxIoSink(sink) as Sink, pretty = false, limit = limit)
}

/**
 * Writes the verbose, indented ([prettyPrint]) rendering of this element as UTF-8 into [sink], truncating after [limit]
 * characters (with a marker). Streaming to a sink lets you produce renderings larger than the in-memory
 * [Asn1Element.prettyPrint]; pass a larger [limit] to render more.
 */
fun Asn1Element.prettyPrint(sink: kotlinx.io.Sink, limit: Long = MAX_RENDER_CHARS) {
    renderTo(KxIoSink(sink) as Sink, pretty = true, limit = limit)
}

/**
 * Decodes an ASN.1 object of type [T] from a DER-encoded source.
 *
 * @param source The source from which the DER-encoded data will be read.
 * @param limit The maximum allowed total number of encoded DER bytes to consume.
 * This limit is enforced before reading or peeking from the underlying source.
 * @param assertTag Optional. If provided, ensures that the decoded element matches this tag.
 * @return The decoded ASN.1 object of type [T].
 * @throws Asn1Exception if the input does not parse or if it exceeds the specified limit.
 * This includes length encoding indicating a length greater than [limit],
 * even if this is malformed and exceeds the number of bytes left in the [source].
 */
@Throws(Asn1Exception::class)
fun <A : Asn1Element, T : Asn1Encodable<A>> at.asitplus.awesn1.Asn1Decodable<A, T>.decodeFromDer(
    source: kotlinx.io.Source,
    limit: Long,
    assertTag: Asn1Element.Tag? = null
): T = decodeFromDer(KxIoSource(source), limit,assertTag)

fun kotlinx.io.Source.decodeAsn1VarULong(): Pair<ULong, ByteArray> =
    KxIoSource(this).decodeAsn1VarULong()

fun kotlinx.io.Source.decodeAsn1VarUInt(): Pair<UInt, ByteArray> =
    KxIoSource(this).decodeAsn1VarUInt()

fun kotlinx.io.Source.decodeAsn1VarBigInt() = KxIoSource(this).decodeAsn1VarBigInt()

fun kotlinx.io.Sink.writeAsn1VarInt(number: UInt): Int =
    KxIoSink(this).writeAsn1VarInt(number)

fun kotlinx.io.Sink.writeAsn1VarInt(number: ULong): Int =
    KxIoSink(this).writeAsn1VarInt(number)
