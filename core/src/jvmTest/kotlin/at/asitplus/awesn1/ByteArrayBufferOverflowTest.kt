package at.asitplus.awesn1

import at.asitplus.awesn1.InternalAwesn1Api
import at.asitplus.awesn1.encoding.internal.ByteArrayBuffer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

@OptIn(InternalAwesn1Api::class)
val ByteArrayBufferOverflowTest by matrixSuite {
    "readByteArray rejects overflowing end index without corrupting state" {
        val buffer = ByteArrayBuffer()
        setIntField(buffer, "readIndex", 2_000_000_000)
        setIntField(buffer, "limit", Int.MAX_VALUE)

        val exception = shouldThrow<IllegalArgumentException> {
            buffer.readByteArray(500_000_000)
        }

        exception.message shouldBe "Cannot read beyond available bytes"
        getIntField(buffer, "readIndex") shouldBe 2_000_000_000
        getIntField(buffer, "limit") shouldBe Int.MAX_VALUE
    }
}

private fun setIntField(target: Any, name: String, value: Int) {
    target.javaClass.getDeclaredField(name).apply {
        isAccessible = true
        setInt(target, value)
    }
}

private fun getIntField(target: Any, name: String): Int =
    target.javaClass.getDeclaredField(name).apply {
        isAccessible = true
    }.getInt(target)
