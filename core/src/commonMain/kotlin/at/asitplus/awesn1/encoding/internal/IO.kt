// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:Suppress("NOTHING_TO_INLINE")

package at.asitplus.awesn1.encoding.internal

import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.ImplementationError
import at.asitplus.awesn1.InternalAwesn1Api

// Conservative max ByteArray length (mirrors the Int.MAX_VALUE - 8 cap used elsewhere); the exact JVM array
// limit is implementation-specific and slightly below Int.MAX_VALUE.
internal const val MAX_BYTE_ARRAY_SIZE: Long = (Int.MAX_VALUE - 8).toLong()

/**
 * Smallest power-of-two capacity >= [required], floored at 32, clamped at MAX_BYTE_ARRAY_SIZE. Pure, no allocation.
 * Throw [Asn1Exception] when [required] exceeds the cap, [IllegalArgumentException] when negative.
 */
@Suppress("NOTHING_TO_INLINE")
internal inline fun nextCapacity(required: Long): Int {
    if(required < 0) throw ImplementationError( "required capacity must be non-negative" )
    if (required > MAX_BYTE_ARRAY_SIZE)
        throw Asn1Exception("ByteArray cannot grow to $required bytes (max $MAX_BYTE_ARRAY_SIZE)")
    if (required <= 32L) return 32
    return (required.takeHighestOneBit() shl 1).coerceAtMost(MAX_BYTE_ARRAY_SIZE).toInt()
}

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
internal class BoundedSource<S : Sink>(
    private val source: Source<S>,
    val limit: Long?,
) : Source<S> {

    var bytesRead = 0L
    private set

    init {
        limit?.let { require(it >= 0) { "Limit must be non-negative" } }
    }

    private val remaining: Long? get() = limit?.let { it - bytesRead }

    private fun requireRemaining(nBytes: Long) {
        require(nBytes >= 0) { "Cannot read a negative number of bytes" }
        if (remaining == null) return
        require(nBytes <= remaining!!) {
            buildString {
                append("Source limit exceeded: requested ")
                append(nBytes)
                append(" bytes with ")
                append(remaining)
                append(" remaining (")
                append(bytesRead)
                append("/")
                append(limit)
                append(" already read)")

            }
        }
    }

    override fun readByte(): Byte {
        requireRemaining(1)
        return source.readByte().also { bytesRead++ }
    }

    /**
     * if the limit is reached, it may still not be exhausted. the limit just limits what can be read.
     * This makes sure that we don't leave dangling bytes when checking for exhaustion
     */
    override fun exhausted() = source.exhausted()

    override fun readByteArray(nBytes: Int): ByteArray {
        requireRemaining(nBytes.toLong())
        return source.readByteArray(nBytes).also { bytesRead += nBytes.toLong() }
    }

    override fun skip(nBytes: Long) {
        requireRemaining(nBytes)
        source.skip(nBytes)
        bytesRead += nBytes
    }

    override fun peek(): BoundedSource<S> = BoundedSource(source.peek(), remaining)

    override fun transferTo(sink: S): Long {
        if (exhausted()) return 0

        if (remaining == null) return source.transferTo(sink)

        var transferred = 0L
        val buffer = ByteArray(8 * 1024) //sensible buffer
        var buffered = 0
        while (remaining!! > 0 && !source.exhausted()) {
            buffer[buffered++] = readByte()
            transferred++
            if (buffered == buffer.size) {
                sink.write(buffer)
                buffered = 0
            }
        }
        if (buffered > 0) {
            sink.write(buffer, endIndex = buffered)
        }
        return transferred
    }
}

@InternalAwesn1Api
inline fun Source<*>.readUByte() = readByte().toUByte()


@InternalAwesn1Api
class ByteArraySink : Sink {
    // ponytail: storage owner for both ByteArraySink and composing ByteArrayBuffer; grow math is in nextCapacity()
    internal var buffer: ByteArray = ByteArray(32)
        private set
    internal var index: Int = 0
        private set

    internal constructor(array: ByteArray, index: Int) {
        require(index in 0..array.size) { "StartIndex must be between 0 and ${array.size}" }
        this.buffer = array
        this.index = index
    }

    constructor() : this(ByteArray(32), 0)

    private fun grow(toAppend: Int) {
        // Compute in Long, fail cleanly past the array limit, and cap the capacity so it can't overflow.
        val required = index.toLong() + toAppend.toLong()
        if (required <= buffer.size) return
        buffer = ByteArray(nextCapacity(required)).also { buffer.copyInto(it, endIndex = index) }
    }

    override fun writeByte(byte: Byte) {
        grow(1)
        buffer[index] = byte
        index++
    }

    override fun write(bytes: ByteArray, startIndex: Int, endIndex: Int) {
        if (startIndex == endIndex) return
        require(startIndex in 0..endIndex) { "StartIndex must be between 0 and $endIndex" }
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

    internal fun reset() { index = 0 }
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
inline fun Sink.writeUByte(uByte: UByte) = writeByte(uByte.toByte())

//turns out, we never used ByteArraySource. it was just dead code.
@InternalAwesn1Api
class ByteArrayBuffer private constructor(
    private val sink: ByteArraySink,
    private var readIndex: Int,
    private var limit: Int,
    private val owner: ByteArrayBuffer?,
    private val ownerGeneration: Int
) : Buffer {

    private var generation: Int = 0
    private var hasActivePeek: Boolean = false

    private val readArray: ByteArray get() = root.sink.buffer

    constructor(initialCapacity: Int = 32) : this(
        sink = ByteArraySink(ByteArray(initialCapacity), 0),
        readIndex = 0,
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
                sink = ByteArraySink(bytes, endIndex),
                readIndex = startIndex,
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

    override fun readByte(): Byte {
        ensureValidPeek()
        if (owner == null) invalidatePeeks()
        check(!exhausted()) { "Source exhausted" }
        return readArray[readIndex++]
    }

    override fun exhausted(): Boolean {
        ensureValidPeek()
        return readIndex >= limit
    }

    override fun readByteArray(nBytes: Int): ByteArray {
        ensureValidPeek()
        require(nBytes >= 0) { "nBytes must be non-negative" }
        if (owner == null) invalidatePeeks()
        val endIndexExclusive = readIndex.toLong() + nBytes.toLong()
        require(endIndexExclusive <= limit.toLong()) { "Cannot read beyond available bytes" }
        return readArray.sliceArray(readIndex until endIndexExclusive.toInt()).also { readIndex = endIndexExclusive.toInt() }
    }

    override fun skip(nBytes: Long) {
        ensureValidPeek()
        require(nBytes >= 0) { "Cannot skip non-positive bytes" }
        require(nBytes <= Int.MAX_VALUE) { "Cannot skip non-positive bytes" }
        if (owner == null) invalidatePeeks()
        require(readIndex + nBytes <= limit) { "Cannot skip beyond size of underlying data" }
        readIndex += nBytes.toInt()
    }

    override fun peek(): Source<Buffer> {
        ensureValidPeek()
        val ownerBuffer = root
        ownerBuffer.hasActivePeek = true
        val generationAtCreation = ownerBuffer.generation
        return ByteArrayBuffer(
            sink = ownerBuffer.sink,
            readIndex = this.readIndex,
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
        sink.write(readArray, readIndex, limit)
        readIndex = limit
        return remaining.toLong()
    }

    override fun writeByte(byte: Byte) {
        ensureWritable()
        sink.writeByte(byte)
        limit = sink.index
    }

    override fun write(bytes: ByteArray, startIndex: Int, endIndex: Int) {
        ensureWritable()
        sink.write(bytes, startIndex, endIndex)
        limit = sink.index
    }

    override fun appendUnsafe(bytes: ByteArray, startIndex: Int, endIndex: Int): Int {
        write(bytes, startIndex, endIndex)
        return endIndex - startIndex
    }

    override fun toByteArray(): ByteArray = ByteArray(sink.index).also {
        sink.buffer.copyInto(it, endIndex = sink.index)
    }

    override fun clear() {
        ensureValidPeek()
        check(owner == null) { "Cannot clear a peek view" }
        invalidatePeeks()
        sink.reset()
        readIndex = 0
        limit = 0
    }

    override fun size(): Int = sink.index

    override fun remaining(): Int {
        ensureValidPeek()
        return limit - readIndex
    }
}
