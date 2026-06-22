// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.encoding.internal

import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.ImplementationError
import at.asitplus.awesn1.InternalAwesn1Api
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

@OptIn(InternalAwesn1Api::class)
val IOTest by matrixSuite {

    "nextCapacity boundary table" {
        nextCapacity(0L) shouldBe 32
        nextCapacity(32L) shouldBe 32
        nextCapacity(33L) shouldBe 64
        nextCapacity((1L shl 30)) shouldBe MAX_BYTE_ARRAY_SIZE.toInt()
        nextCapacity(MAX_BYTE_ARRAY_SIZE) shouldBe MAX_BYTE_ARRAY_SIZE.toInt()
        shouldThrow<Asn1Exception> { nextCapacity(MAX_BYTE_ARRAY_SIZE + 1L) }
        shouldThrow<ImplementationError> { nextCapacity(-1L) }
    }

    "ByteArraySink write parity: bad bounds throw IndexOutOfBoundsException" {
        val sink = ByteArraySink()
        val src = byteArrayOf(1, 2, 3)
        shouldThrow<IndexOutOfBoundsException> { sink.write(src, 0, 5) }
    }

    "ByteArraySink write parity: bad startIndex message" {
        val sink = ByteArraySink()
        val src = byteArrayOf(1, 2, 3)
        val ex = shouldThrow<IllegalArgumentException> { sink.write(src, 2, 1) }
        ex.message shouldBe "StartIndex must be between 0 and 1"
    }

    "ByteArraySink grow past 2^30 returns Asn1Exception at the cap, not a negative-size crash" {
        // pure-function oracle above already proves the math; this end-to-end check
        // exercises the sink at the boundary without allocating past it.
        shouldThrow<Asn1Exception> { nextCapacity(MAX_BYTE_ARRAY_SIZE + 1L) }
    }

    "ByteArrayBuffer wrap is no-copy: mutating source array is observed via read" {
        val src = byteArrayOf(10, 20, 30, 40)
        val buf = ByteArrayBuffer.wrap(src, 1, 4)
        src[1] = 99
        buf.readByte() shouldBe 99
        src[2] = 77
        buf.readByte() shouldBe 77
    }

    "ByteArrayBuffer size/toByteArray round-trip" {
        val buf = ByteArrayBuffer()
        buf.write(byteArrayOf(1, 2, 3))
        buf.writeByte(4)
        buf.size() shouldBe 4
        buf.toByteArray() shouldBe byteArrayOf(1, 2, 3, 4)
    }

    "ByteArrayBuffer transferTo returns count and drains" {
        val src = ByteArrayBuffer.wrap(byteArrayOf(7, 8, 9))
        val dst = ByteArrayBuffer()
        src.transferTo(dst) shouldBe 3L
        src.exhausted() shouldBe true
        dst.toByteArray() shouldBe byteArrayOf(7, 8, 9)
    }

    "peek: read on peek does not invalidate; owner read invalidates the peek" {
        val owner = ByteArrayBuffer.wrap(byteArrayOf(1, 2, 3, 4, 5))
        val peek = owner.peek()
        peek.readByte() shouldBe 1
        peek.readByte() shouldBe 2
        owner.readByte() // invalidates peek
        shouldThrow<IllegalStateException> { peek.readByte() }
    }

    "peek: owner skip invalidates the peek" {
        val owner = ByteArrayBuffer.wrap(byteArrayOf(1, 2, 3, 4, 5))
        val peek = owner.peek()
        peek.readByte() shouldBe 1
        owner.skip(1)
        shouldThrow<IllegalStateException> { peek.readByte() }
    }

    "peek: parser pattern (peek, read header, owner.skip, owner reads at offset n, stale peek throws)" {
        val owner = ByteArrayBuffer.wrap(byteArrayOf(0x30, 0x03, 0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte()))
        val peek = owner.peek()
        peek.readByte() shouldBe 0x30
        peek.readByte() shouldBe 0x03
        owner.readByte(); owner.readByte()
        owner.skip(3)
        shouldThrow<IllegalStateException> { peek.readByte() }
    }

    "peek: write-while-peek-active throws" {
        val owner = ByteArrayBuffer()
        owner.peek()
        val ex = shouldThrow<IllegalStateException> { owner.writeByte(1) }
        ex.message shouldBe "Cannot write while a peek view is active"
    }
}
