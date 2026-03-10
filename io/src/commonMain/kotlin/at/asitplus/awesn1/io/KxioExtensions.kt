// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(at.asitplus.awesn1.InternalAwesn1Api::class)

package at.asitplus.awesn1.io

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Encodable
import at.asitplus.awesn1.encoding.KxIoSink
import at.asitplus.awesn1.encoding.KxIoSource
import at.asitplus.awesn1.encoding.internal.*

fun Asn1Element.Companion.parse(source: kotlinx.io.Source): Asn1Element =
    parse(KxIoSource(source) as Source<*>)

fun Asn1Element.Companion.parseAll(source: kotlinx.io.Source): List<Asn1Element> =
    parseAll(KxIoSource(source) as Source<*>)

fun Asn1Element.Companion.parseFirst(source: kotlinx.io.Source): Pair<Asn1Element, Long> =
    parseFirst(KxIoSource(source) as Source<*>)

fun kotlinx.io.Source.readAsn1Element(): Pair<Asn1Element, Long> =
    KxIoSource(this).readAsn1Element()

fun kotlinx.io.Source.readFullyToAsn1Elements(): Pair<List<Asn1Element>, Long> =
    KxIoSource(this).readFullyToAsn1Elements()

fun Asn1Encodable<*>.encodeToDer(sink: kotlinx.io.Sink) {
    encodeToDer(KxIoSink(sink) as Sink)
}

fun Asn1Element.encodeToDer(sink: kotlinx.io.Sink) {
    encodeTo(KxIoSink(sink) as Sink)
}

fun <A : Asn1Element, T : Asn1Encodable<A>> at.asitplus.awesn1.Asn1Decodable<A, T>.decodeFromDer(
    source: kotlinx.io.Source,
    assertTag: Asn1Element.Tag? = null
): T = decodeFromDer(KxIoSource(source), assertTag)

fun kotlinx.io.Source.decodeAsn1VarULong(): Pair<ULong, ByteArray> =
    KxIoSource(this).decodeAsn1VarULong()

fun kotlinx.io.Source.decodeAsn1VarUInt(): Pair<UInt, ByteArray> =
    KxIoSource(this).decodeAsn1VarUInt()

fun kotlinx.io.Source.decodeAsn1VarBigInt() = KxIoSource(this).decodeAsn1VarBigInt()

fun kotlinx.io.Sink.writeAsn1VarInt(number: UInt): Int =
    KxIoSink(this).writeAsn1VarInt(number)

fun kotlinx.io.Sink.writeAsn1VarInt(number: ULong): Int =
    KxIoSink(this).writeAsn1VarInt(number)
