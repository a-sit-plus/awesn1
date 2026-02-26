package at.asitplus.awesn1

import at.asitplus.awesn1.encoding.ByteArraySink
import at.asitplus.awesn1.encoding.ByteArraySource
import at.asitplus.awesn1.encoding.Source

/**
 * Directly moves the byte array to a buffer without copying. Thus, it keeps bytes managed by a Buffer accessible.
 * The bytes may be overwritten through the Buffer or even recycled to be used by another buffer.
 * Therefore, operating on these bytes after wrapping leads to undefined behaviour.
 */
//Dunno, maybe a real source would be nice
fun ByteArray.wrapInUnsafeSource(): Source<*> = wrapInUnsafeSource(this)

/**
 * Directly moves the byte array to a buffer without copying. Thus, it keeps bytes managed by a Buffer accessible.
 * The bytes may be overwritten through the Buffer or even recycled to be used by another buffer.
 * Therefore, operating on these bytes after wrapping leads to undefined behaviour.
 * [startIndex] is inclusive, [endIndex] is exclusive.
 */
internal fun wrapInUnsafeSource(bytes: ByteArray, startIndex: Int = 0, endIndex: Int = bytes.size) = ByteArraySource(bytes, startIndex, endIndex-1)

/**
 * Helper to create a buffer, operate on it and return its contents as a [ByteArray]
 */
//a buffer would be nice here
internal inline fun throughBuffer(operation: (ByteArraySink) -> Unit): ByteArray =
    ByteArraySink().also(operation).readByteArray()


/** Drops bytes at the start, or adds zero bytes at the start, until the [size] is reached */
fun ByteArray.ensureSize(size: Int): ByteArray = (this.size - size).let { toDrop ->
    when {
        toDrop > 0 -> this.copyOfRange(toDrop, this.size)
        toDrop < 0 -> ByteArray(-toDrop) + this
        else -> this
    }
}