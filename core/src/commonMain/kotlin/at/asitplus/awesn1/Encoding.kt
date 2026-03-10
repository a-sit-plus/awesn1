// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(at.asitplus.awesn1.InternalAwesn1Api::class)

package at.asitplus.awesn1

import at.asitplus.awesn1.encoding.internal.ByteArrayBuffer
import at.asitplus.awesn1.encoding.internal.Source
import at.asitplus.awesn1.encoding.internal.Sink

/**
 * Directly moves the byte array to a buffer without copying. Thus, it keeps bytes managed by a Buffer accessible.
 * The bytes may be overwritten through the Buffer or even recycled to be used by another buffer.
 * Therefore, operating on these bytes after wrapping leads to undefined behaviour.
 */
fun ByteArray.wrapInUnsafeSource(): Source<*> = wrapInUnsafeSource(this)

/**
 * Directly moves the byte array to a buffer without copying. Thus, it keeps bytes managed by a Buffer accessible.
 * The bytes may be overwritten through the Buffer or even recycled to be used by another buffer.
 * Therefore, operating on these bytes after wrapping leads to undefined behaviour.
 * [startIndex] is inclusive, [endIndex] is exclusive.
 */
internal fun wrapInUnsafeSource(bytes: ByteArray, startIndex: Int = 0, endIndex: Int = bytes.size): Source<*> =
    ByteArrayBuffer.wrap(bytes, startIndex, endIndex)

/**
 * Helper to create a buffer, operate on it and return its contents as a [ByteArray]
 */
internal inline fun throughBuffer(operation: (Sink) -> Unit): ByteArray =
    ByteArrayBuffer().also(operation).toByteArray()

internal inline fun <reified T> ByteArray.throughBuffer(operation: (Source<*>) -> T): T =
    operation(wrapInUnsafeSource())


/** Drops bytes at the start, or adds zero bytes at the start, until the [size] is reached */
fun ByteArray.ensureSize(size: Int): ByteArray = (this.size - size).let { toDrop ->
    when {
        toDrop > 0 -> this.copyOfRange(toDrop, this.size)
        toDrop < 0 -> ByteArray(-toDrop) + this
        else -> this
    }
}
