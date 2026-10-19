// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(ExperimentalSerializationApi::class)

package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.encoding.parse
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.encodeToByteArray


// Suite names preserve the original finding identifiers.
val built_in_element_tree_depth_limits by matrixSuite {
    val der = DER { maxNestingDepth = 8 }
    val deep = nestedSequenceDer(9)

    "Encoding a built-in element tree beyond maxNestingDepth is rejected" {
        val element = Asn1Element.parse(deep)
        shouldThrow<SerializationException> { der.encodeToByteArray(Asn1Element.serializer(), element) }
    }

    "Decoding a built-in element tree beyond maxNestingDepth is rejected" {
        shouldThrow<SerializationException> { der.decodeFromByteArray(Asn1Element.serializer(), deep) }
    }
}

private fun nestedSequenceDer(levels: Int): ByteArray {
    var sequence = Asn1Sequence(emptyList())
    repeat(levels - 1) { sequence = Asn1Sequence(listOf(sequence)) }
    return sequence.derEncoded
}

@Serializable
private data class DsPlainRecursive(val child: DsPlainRecursive? = null)

val depthguard_soe_bypass by matrixSuite {
    "Deep recursive decoding on a small stack throws a catchable SerializationException" {
        onThreadWithStack(64 * 1024L) {
            DER.decodeFromDer<DsPlainRecursive>(nestedSequenceDer(127))
        }.shouldBeInstanceOf<SerializationException>()
    }
}

val enc_depthguard_soe_smallstack by matrixSuite {
    "Deep recursive encoding on a small stack throws a catchable SerializationException" {
        var graph = DsPlainRecursive()
        repeat(126) { graph = DsPlainRecursive(graph) }
        onThreadWithStack(64 * 1024L) {
            DER.encodeToByteArray(graph)
        }.shouldBeInstanceOf<SerializationException>()
    }
}

private fun onThreadWithStack(stackSize: Long, block: () -> Unit): Throwable? {
    var escaped: Throwable? = null
    val thread = Thread(null, {
        try {
            block()
        } catch (t: Throwable) {
            escaped = t
        }
    }, "awesn1-small-stack", stackSize)
    thread.start()
    thread.join()
    return escaped
}

val max_nesting_depth_guard_silent_disable by matrixSuite {
    "The maximum supported nesting depth can be configured" {
        DER { maxNestingDepth = 65_536 }.configuration.maxNestingDepth shouldBe 65_536
    }

    "A nesting depth outside the supported range is rejected" {
        shouldThrow<IllegalArgumentException> { DER { maxNestingDepth = Int.MAX_VALUE } }
    }
}

@Serializable
private data class DsWrappedOctet(val payload: ByteArray)

val der_maxinput_unbounded by matrixSuite {
    val payload = DER.encodeToByteArray(DsWrappedOctet(ByteArray(1024 * 1024)))

    "A configured input cap rejects a payload exceeding it" {
        shouldThrow<SerializationException> {
            DER { maxInputLength = 1024L }.decodeFromDer<DsWrappedOctet>(payload)
        }
    }

    "The default input cap accepts a one MiB payload" {
        DER.decodeFromDer<DsWrappedOctet>(payload).payload.size shouldBe 1024 * 1024
    }

    "The JVM default input cap is below Int.MAX_VALUE" {
        (DER.configuration.maxInputLength < Int.MAX_VALUE.toLong()) shouldBe true
    }
}
