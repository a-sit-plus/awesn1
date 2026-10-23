// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(ExperimentalStdlibApi::class)

package at.asitplus.awesn1

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json

val bitset_boxed_byte_retained_amplification by matrixSuite {
    "Converting a BIT STRING allocates packed storage" {
        val contentSize = 4 * 1024 * 1024
        val bitString = Asn1BitString(ByteArray(contentSize) { 0xFF.toByte() })
        var bitSet: BitSet? = null
        val allocated = allocatedBytes { bitSet = bitString.toBitSet() }
        bitSet!!.toLsb0ByteArray().size shouldBe contentSize
        (allocated < contentSize.toLong() * 3) shouldBe true
    }
}

val bitset_deserialize_quadratic_zero_run_dos_v3 by matrixSuite {
    val size = 16_384

    "Dense BIT STRING content converts within the processing budget" {
        val elapsed = measureMillis {
            Json.decodeFromString(Asn1BitString.serializer(), "\"0:${base64(ByteArray(size) { 0xFF.toByte() })}\"")
                .toBitSet()
        }
        (elapsed < 2_000) shouldBe true
    }

    "A sparse BIT STRING converts within the same processing budget" {
        val elapsed = measureMillis {
            Json.decodeFromString(Asn1BitString.serializer(), "\"0:${base64(ByteArray(size).also { it[size - 1] = 1 })}\"")
                .toBitSet()
        }
        (elapsed < 2_000) shouldBe true
    }

    "Repeated high-bit writes do not repeatedly grow and trim storage" {
        val elapsed = measureMillis {
            val bits = BitSet()
            repeat(200) {
                bits[8_000_000L] = true
                bits[8_000_000L] = false
            }
        }
        (elapsed < 2_000) shouldBe true
    }
}

val bitset_fromstring_quadratic_cpu_dos by matrixSuite {
    "An all-ones logical string parses within the processing budget" {
        (measureMillis { BitSet.fromLogicalBitString("1".repeat(1_000_000)) } < 2_000) shouldBe true
    }

    "A logical string with a long zero run parses within the processing budget" {
        (measureMillis { BitSet.fromLogicalBitString("1" + "0".repeat(99_999)) } < 2_000) shouldBe true
    }
}

val bitset_negative_set_silent_noop by matrixSuite {
    "A negative bit index cannot be read" {
        shouldThrow<IndexOutOfBoundsException> { BitSet()[-1L] }
    }

    for (index in listOf(-1L, -3L)) {
        "A negative bit index $index cannot be written" {
            shouldThrow<IndexOutOfBoundsException> { BitSet()[index] = true }
        }
    }
}

val bitstring_fallback_deserializer_leaks_non_serialization_exceptions by matrixSuite {
    for (payload in listOf("6:IA==", "1", "99999999999999:AAAA", "1:!!!", "-1:AAAA")) {
        "Malformed BIT STRING text $payload fails as SerializationException" {
            shouldThrow<SerializationException> {
                Json.decodeFromString(Asn1BitString.serializer(), "\"$payload\"")
            }
        }
    }
}

private fun base64(bytes: ByteArray): String = java.util.Base64.getEncoder().encodeToString(bytes)

private fun measureMillis(block: () -> Unit): Long {
    val start = System.nanoTime()
    block()
    return (System.nanoTime() - start) / 1_000_000
}

/** HotSpot's per-thread allocation counter excludes unrelated concurrent allocations. */
private fun allocatedBytes(block: () -> Unit): Long {
    val bean = java.lang.management.ManagementFactory.getThreadMXBean() as com.sun.management.ThreadMXBean
    val id = Thread.currentThread().id
    val before = bean.getThreadAllocatedBytes(id)
    block()
    return bean.getThreadAllocatedBytes(id) - before
}
