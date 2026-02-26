package at.asitplus.awesn1.encoding

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

val ByteArrayIoTest by testSuite {

    "ByteArraySource.readByte and exhausted" {
        val source = ByteArraySource(byteArrayOf(0x01, 0x02, 0x03))

        source.exhausted() shouldBe false
        source.readByte() shouldBe 0x01.toByte()
        source.exhausted() shouldBe false
        source.readByte() shouldBe 0x02.toByte()
        source.exhausted() shouldBe false
        source.readByte() shouldBe 0x03.toByte()
        source.exhausted() shouldBe true
    }

    "ByteArraySource.readByteArray and skip" {
        val source = ByteArraySource(byteArrayOf(1, 2, 3, 4, 5))

        source.readByteArray(2) shouldBe byteArrayOf(1, 2)
        source.skip(2L)
        source.readByte() shouldBe 5.toByte()
        source.exhausted() shouldBe true
    }

    "ByteArraySource.skip validates input" {
        val source = ByteArraySource(byteArrayOf(1, 2, 3))

        shouldThrow<IllegalArgumentException> { source.skip(-1L) }
        source.skip(3L)
        source.exhausted() shouldBe true
        shouldThrow<IllegalArgumentException> { source.skip(1L) }
    }

    "ByteArraySource.peek does not consume original" {
        val source = ByteArraySource(byteArrayOf(10, 20, 30, 40))

        source.readByte() shouldBe 10.toByte()
        val peek = source.peek()

        peek.readByteArray(2) shouldBe byteArrayOf(20, 30)
        source.readByteArray(2) shouldBe byteArrayOf(20, 30)
        source.readByte() shouldBe 40.toByte()
    }

    "ByteArraySource.transferTo writes remaining bytes and consumes source" {
        val source = ByteArraySource(byteArrayOf(9, 8, 7, 6))
        val sink = ByteArraySink()

        source.readByte() shouldBe 9.toByte()
        source.transferTo(sink) shouldBe 3L
        sink.readByteArray() shouldBe byteArrayOf(8, 7, 6)
        source.exhausted() shouldBe true
        source.transferTo(ByteArraySink()) shouldBe 0L
    }

    "ByteArraySink.writeByte writes bytes in order" {
        val sink = ByteArraySink()

        sink.writeByte(0x11.toByte())
        sink.writeByte(0x22.toByte())
        sink.writeByte(0x33.toByte())

        sink.readByteArray() shouldBe byteArrayOf(0x11, 0x22, 0x33)
    }

    "ByteArraySink.write writes selected range" {
        val sink = ByteArraySink()

        sink.write(byteArrayOf(5, 6, 7, 8), startIndex = 1, endIndex = 3)
        sink.readByteArray() shouldBe byteArrayOf(6, 7)
    }

    "ByteArraySink.write validates range" {
        val sink = ByteArraySink()

        shouldThrow<IllegalArgumentException> {
            sink.write(byteArrayOf(1, 2, 3), startIndex = 2, endIndex = 1)
        }
        shouldThrow<IndexOutOfBoundsException> {
            sink.write(byteArrayOf(1, 2, 3), startIndex = 1, endIndex = 4)
        }
        shouldThrow<IllegalArgumentException> {
            sink.write(byteArrayOf(1, 2, 3), startIndex = -1, endIndex = 2)
        }
    }

    "ByteArraySink.appendUnsafe appends and returns written count" {
        val sink = ByteArraySink()

        sink.appendUnsafe(byteArrayOf(1, 2, 3, 4), startIndex = 1, endIndex = 4) shouldBe 3
        sink.readByteArray() shouldBe byteArrayOf(2, 3, 4)
    }

    "ByteArraySink grows for large writes" {
        val sink = ByteArraySink()
        val input = ByteArray(128) { it.toByte() }

        sink.write(input)
        sink.readByteArray() shouldBe input
    }
}
