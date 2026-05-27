package at.asitplus.awesn1.hardening

import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.InternalAwesn1Api
import at.asitplus.awesn1.encoding.internal.BoundedSource
import at.asitplus.awesn1.encoding.internal.ByteArraySink
import at.asitplus.awesn1.encoding.internal.Source
import at.asitplus.awesn1.encoding.internal.parse
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

@OptIn(InternalAwesn1Api::class)
val BoundedSourceTest by testSuite {
    "bounded source enforces exact limit" {
        val source = CountingSource(byteArrayOf(1, 2, 3))
        val bounded = BoundedSource(source, 2)

        bounded.readByte() shouldBe 1
        bounded.readByte() shouldBe 2
        bounded.exhausted() shouldBe false //because limit does not mean exhaustion!
        shouldThrow<IllegalArgumentException> {
            bounded.readByte()
        }
        source.readCount shouldBe 2
    }

    "bounded source rejects readByteArray overshoot before reading upstream" {
        val source = CountingSource(byteArrayOf(1, 2, 3))
        val bounded = BoundedSource(source, 2)

        shouldThrow<IllegalArgumentException> {
            bounded.readByteArray(3)
        }
        source.readCount shouldBe 0
    }

    "bounded source rejects skip overshoot before reading upstream" {
        val source = CountingSource(byteArrayOf(1, 2, 3))
        val bounded = BoundedSource(source, 2)

        shouldThrow<IllegalArgumentException> {
            bounded.skip(3)
        }
        source.readCount shouldBe 0
    }

    "bounded source peek cannot read past remaining limit and does not advance parent" {
        val source = CountingSource(byteArrayOf(1, 2, 3))
        val bounded = BoundedSource(source, 2)
        val peek = bounded.peek()

        peek.readByte() shouldBe 1
        peek.readByte() shouldBe 2
        shouldThrow<IllegalArgumentException> {
            peek.readByte()
        }
        source.readCount shouldBe 2
        bounded.readByte() shouldBe 1
        source.readCount shouldBe 3
    }

    "bounded source transferTo copies at most limit" {
        val source = CountingSource(byteArrayOf(1, 2, 3, 4, 5))
        val bounded = BoundedSource(source, 4)
        val sink = ByteArraySink()

        bounded.transferTo(sink) shouldBe 4L
        sink.readByteArray().toList() shouldBe listOf<Byte>(1, 2, 3, 4)
        source.readCount shouldBe 4
    }

    "bounded source invoke with null limit returns source" {
        val source = CountingSource(byteArrayOf(1, 2, 3))
        val unbounded: Source<ByteArraySink> = BoundedSource(source, null)
        val bounded: Source<ByteArraySink> = BoundedSource(source, 1)

        (unbounded === source) shouldBe true
        (bounded === source) shouldBe false
    }

    "der parser does not peek past bounded parent length" {
        val source = CountingSource(byteArrayOf(0x30, 0x02, 0x1f, 0x81.toByte(), 0x00))

        shouldThrow<Asn1Exception> {
            Asn1Element.parse(source, 5)
        }
        source.readCount shouldBe 4
    }
}

@OptIn(InternalAwesn1Api::class)
private class CountingSource private constructor(
    private val data: ByteArray,
    private var index: Int = 0,
    private val counter: Counter
) : Source<ByteArraySink> {

    constructor(data: ByteArray) : this(data, 0, Counter())

    val readCount: Long get() = counter.readCount

    override fun readByte(): Byte {
        check(!exhausted()) { "Source exhausted" }
        counter.readCount++
        return data[index++]
    }

    override fun exhausted(): Boolean = index >= data.size

    override fun readByteArray(nBytes: Int): ByteArray {
        require(nBytes >= 0) { "nBytes must be non-negative" }
        require(index + nBytes <= data.size) { "Cannot read beyond available bytes" }
        counter.readCount += nBytes.toLong()
        return data.sliceArray(index until index + nBytes).also { index += nBytes }
    }

    override fun skip(nBytes: Long) {
        require(nBytes >= 0) { "Cannot skip non-positive bytes" }
        require(index + nBytes <= data.size) { "Cannot skip beyond size of underlying data" }
        counter.readCount += nBytes
        index += nBytes.toInt()
    }

    override fun peek(): Source<ByteArraySink> = CountingSource(data, index, counter)

    override fun transferTo(sink: ByteArraySink): Long {
        var transferred = 0L
        while (!exhausted()) {
            sink.writeByte(readByte())
            transferred++
        }
        return transferred
    }

    private class Counter {
        var readCount = 0L
    }
}
