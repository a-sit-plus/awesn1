// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:Suppress("NOTHING_TO_INLINE")

// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.encoding.internal

import at.asitplus.awesn1.InternalAwesn1Api

@InternalAwesn1Api
interface Source<S : Sink> {
    fun readByte(): Byte
    fun exhausted(): Boolean
    fun readByteArray(nBytes: Int): ByteArray
    fun skip(nBytes: Long)

    /**
     * Returns a new Source that can read data from this source without consuming it. The returned source becomes invalid once this source is next read or closed.
     */
    fun peek(): Source<S>

    /**
     * Removes all bytes from this source, writes them to sink, and returns the total number of bytes written to sink.
     * Return 0 if this source is exhausted.
     */
    fun transferTo(sink: S): Long
}


@InternalAwesn1Api
inline fun Source<*>.readUByte() = readByte().toUByte()


@InternalAwesn1Api
class ByteArraySource(
    private val data: ByteArray,
    private var index: Int = 0,
    private val size: Int = data.size
) : Source<ByteArraySink> {

    override fun readByte(): Byte = data[index].also { index++ }

    override fun exhausted(): Boolean = index >= size

    override fun readByteArray(nBytes: Int): ByteArray =
        data.sliceArray(index until index + nBytes).also { index += nBytes }


    override fun skip(nBytes: Long) {
        require(nBytes >= 0) { "Cannot skip non-positive bytes" }
        require(nBytes < Int.MAX_VALUE) { "Cannot skip non-positive bytes" }
        require((nBytes + index.toLong()) <= size.toLong()) { "Cannot skip beyond size of underlying data" }
        index += nBytes.toInt()
    }

    override fun peek(): ByteArraySource = ByteArraySource(data.sliceArray(index until size))
    override fun transferTo(sink: ByteArraySink): Long {
        if (exhausted()) return 0
        sink.write(data, index, size)
        return ((size - index).also { index = size }).toLong()
    }

}

@InternalAwesn1Api
interface Sink {
    fun writeByte(byte: Byte)
    fun write(bytes: ByteArray, startIndex: Int = 0, endIndex: Int = bytes.size)

    /**
     * Directly appends [bytes] to this Sink's internal Buffer without copying. Thus, it keeps bytes managed by a Buffer accessible.
     * The bytes may be overwritten through the Buffer or even recycled to be used by another buffer.
     * Therefore, operating on these bytes after wrapping leads to undefined behaviour.
     * [startIndex] is inclusive, [endIndex] is exclusive.
     *
     * @return [endIndex] - [startIndex]
     */
    fun appendUnsafe(bytes: ByteArray, startIndex: Int = 0, endIndex: Int = bytes.size): Int
}

@InternalAwesn1Api
interface Buffer : Source<Buffer>, Sink {
    fun toByteArray(): ByteArray
    fun clear()
    fun size(): Int
    fun remaining(): Int
}

@InternalAwesn1Api
class ByteArraySink : Sink {
    private var buffer: ByteArray = ByteArray(32)
    private var index: Int = 0
    private fun grow(toAppend: Int) {
        if (index + toAppend <= buffer.size) {
            return
        }
        buffer = ByteArray((index + toAppend).takeHighestOneBit() shl 1).let {
            buffer.copyInto(it)
        }
    }

    override fun writeByte(byte: Byte) {
        grow(1)
        buffer[index] = byte
        index++
    }

    override fun write(bytes: ByteArray, startIndex: Int, endIndex: Int) {
        if(startIndex==endIndex) return
        require(startIndex in 0 .. endIndex) { "StartIndex must be between 0 and $endIndex" }
        val length = endIndex - startIndex
        if (startIndex < 0 || startIndex > bytes.size || length < 0
            || length > bytes.size - startIndex
        ) {
            throw IndexOutOfBoundsException()
        }

        grow(length)
        bytes.copyInto(
            destination = buffer,
            destinationOffset = index,
            startIndex = startIndex,
            endIndex = endIndex
        )
        index += length
    }

    override fun appendUnsafe(bytes: ByteArray, startIndex: Int, endIndex: Int): Int {
        write(bytes, startIndex, endIndex)
        return endIndex - startIndex
    }

    fun readByteArray(): ByteArray = ByteArray(index).let {
        buffer.copyInto(it, startIndex = 0, endIndex = index)
    }

}

@InternalAwesn1Api
inline fun Sink.writeUByte(uByte: UByte) = writeByte(uByte.toByte())

@InternalAwesn1Api
class ByteArrayBuffer private constructor(
    private var buffer: ByteArray,
    private var readIndex: Int,
    private var writeIndex: Int,
    private var limit: Int,
    private val owner: ByteArrayBuffer?,
    private val ownerGeneration: Int
) : Buffer {

    private var generation: Int = 0
    private var hasActivePeek: Boolean = false

    constructor(initialCapacity: Int = 32) : this(
        buffer = ByteArray(initialCapacity),
        readIndex = 0,
        writeIndex = 0,
        limit = 0,
        owner = null,
        ownerGeneration = 0
    )

    companion object {
        @InternalAwesn1Api
        fun wrap(bytes: ByteArray, startIndex: Int = 0, endIndex: Int = bytes.size): ByteArrayBuffer {
            require(startIndex in 0..endIndex) { "Invalid source bounds: [$startIndex, $endIndex)" }
            require(endIndex <= bytes.size) { "End index $endIndex out of bounds for size ${bytes.size}" }
            return ByteArrayBuffer(
                buffer = bytes,
                readIndex = startIndex,
                writeIndex = endIndex,
                limit = endIndex,
                owner = null,
                ownerGeneration = 0
            )
        }
    }

    private val root: ByteArrayBuffer get() = owner ?: this
    private val isPeekView: Boolean get() = owner != null

    private fun ensureValidPeek() {
        if (owner != null && owner.generation != ownerGeneration) {
            throw IllegalStateException("Peek source is no longer valid")
        }
    }

    private fun invalidatePeeks() {
        generation++
        hasActivePeek = false
    }

    private fun ensureWritable() {
        ensureValidPeek()
        check(!isPeekView) { "Writing to a peeked buffer is not supported" }
        check(!hasActivePeek) { "Cannot write while a peek view is active" }
    }

    private fun ensureCapacity(toAppend: Int) {
        val needed = writeIndex + toAppend
        if (needed <= buffer.size) return
        val newSize = (needed.takeHighestOneBit() shl 1).coerceAtLeast(32)
        buffer = ByteArray(newSize).also { buffer.copyInto(it, endIndex = writeIndex) }
        limit = writeIndex
    }

    override fun readByte(): Byte {
        ensureValidPeek()
        if (owner == null) invalidatePeeks()
        check(!exhausted()) { "Source exhausted" }
        return buffer[readIndex++]
    }

    override fun exhausted(): Boolean {
        ensureValidPeek()
        return readIndex >= limit
    }

    override fun readByteArray(nBytes: Int): ByteArray {
        ensureValidPeek()
        require(nBytes >= 0) { "nBytes must be non-negative" }
        if (owner == null) invalidatePeeks()
        require(readIndex + nBytes <= limit) { "Cannot read beyond available bytes" }
        return buffer.sliceArray(readIndex until readIndex + nBytes).also { readIndex += nBytes }
    }

    override fun skip(nBytes: Long) {
        ensureValidPeek()
        require(nBytes >= 0) { "Cannot skip non-positive bytes" }
        require(nBytes <= Int.MAX_VALUE) { "Cannot skip non-positive bytes" }
        if (owner == null) invalidatePeeks()
        require(readIndex + nBytes <= limit) { "Cannot skip beyond size of underlying data" }
        readIndex += nBytes.toInt()
    }

    override fun peek(): Buffer {
        ensureValidPeek()
        val ownerBuffer = root
        ownerBuffer.hasActivePeek = true
        val generationAtCreation = ownerBuffer.generation
        return ByteArrayBuffer(
            buffer = ownerBuffer.buffer,
            readIndex = this.readIndex,
            writeIndex = ownerBuffer.writeIndex,
            limit = this.limit,
            owner = ownerBuffer,
            ownerGeneration = generationAtCreation
        )
    }

    override fun transferTo(sink: Buffer): Long {
        ensureValidPeek()
        if (owner == null) invalidatePeeks()
        if (exhausted()) return 0
        val remaining = limit - readIndex
        sink.write(buffer, readIndex, limit)
        readIndex = limit
        return remaining.toLong()
    }

    override fun writeByte(byte: Byte) {
        ensureWritable()
        ensureCapacity(1)
        buffer[writeIndex++] = byte
        limit = writeIndex
    }

    override fun write(bytes: ByteArray, startIndex: Int, endIndex: Int) {
        ensureWritable()
        if (startIndex == endIndex) return
        require(startIndex in 0..endIndex) { "StartIndex must be between 0 and $endIndex" }
        val length = endIndex - startIndex
        if (startIndex < 0 || startIndex > bytes.size || length < 0
            || length > bytes.size - startIndex
        ) {
            throw IndexOutOfBoundsException()
        }
        ensureCapacity(length)
        bytes.copyInto(
            destination = buffer,
            destinationOffset = writeIndex,
            startIndex = startIndex,
            endIndex = endIndex
        )
        writeIndex += length
        limit = writeIndex
    }

    override fun appendUnsafe(bytes: ByteArray, startIndex: Int, endIndex: Int): Int {
        write(bytes, startIndex, endIndex)
        return endIndex - startIndex
    }

    override fun toByteArray(): ByteArray = ByteArray(writeIndex).also {
        buffer.copyInto(it, endIndex = writeIndex)
    }

    override fun clear() {
        ensureValidPeek()
        check(owner == null) { "Cannot clear a peek view" }
        invalidatePeeks()
        readIndex = 0
        writeIndex = 0
        limit = 0
    }

    override fun size(): Int = writeIndex

    override fun remaining(): Int {
        ensureValidPeek()
        return limit - readIndex
    }
}
