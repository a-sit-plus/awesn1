package at.asitplus.awesn1.encoding


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

inline fun Source<*>.readUByte() = readByte().toUByte()

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

inline fun Sink.writeUByte(uByte: UByte) = writeByte(uByte.toByte())
