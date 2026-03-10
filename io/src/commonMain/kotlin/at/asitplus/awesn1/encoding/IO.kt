// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(UnsafeIoApi::class, DelicateIoApi::class)

package at.asitplus.awesn1.encoding

import at.asitplus.awesn1.InternalAwesn1Api
import at.asitplus.awesn1.encoding.internal.Sink
import at.asitplus.awesn1.encoding.internal.Source
import kotlinx.io.DelicateIoApi
import kotlinx.io.UnsafeIoApi
import kotlinx.io.readByteArray
import kotlinx.io.unsafe.UnsafeBufferOperations
import kotlinx.io.writeToInternalBuffer
import kotlin.jvm.JvmInline

@JvmInline

@InternalAwesn1Api
value class KxIoSource(val source: kotlinx.io.Source) : Source<KxIoSink> {
    override fun readByte(): Byte = source.readByte()

    override fun exhausted(): Boolean = source.exhausted()

    override fun readByteArray(nBytes: Int): ByteArray = source.readByteArray(nBytes)

    override fun skip(nBytes: Long) = source.skip(nBytes)

    override fun peek(): KxIoSource = KxIoSource(source.peek())
    override fun transferTo(sink: KxIoSink): Long =source.transferTo(sink.sink)

}


@InternalAwesn1Api
class KxIoSink(internal val sink: kotlinx.io.Sink) : Sink {
    override fun writeByte(byte: Byte) =sink.writeByte(byte)

    override fun write(bytes: ByteArray, startIndex: Int, endIndex: Int)=sink.write(bytes, startIndex, endIndex)

    override fun appendUnsafe(bytes: ByteArray, startIndex: Int, endIndex: Int): Int {
        require(startIndex in 0..<endIndex) { "StartIndex must be between 0 and $endIndex" }
        sink.writeToInternalBuffer {
            UnsafeBufferOperations.moveToTail(it, bytes, startIndex, endIndex)
        }
        return endIndex - startIndex
    }
}
