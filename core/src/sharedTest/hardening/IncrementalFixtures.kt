package at.asitplus.awesn1.hardening

import at.asitplus.awesn1.InternalAwesn1Api
import at.asitplus.awesn1.encoding.internal.ByteArraySink
import at.asitplus.awesn1.encoding.internal.Source

/** Counts committed bytes separately from the furthest byte inspected by temporary peeks. */
@OptIn(InternalAwesn1Api::class)
class InspectingSource private constructor(
    private val bytes: ByteArray,
    private var index: Int,
    private val state: State,
    private val isPeek: Boolean,
) : Source<ByteArraySink> {
    constructor(bytes: ByteArray, forbiddenFrom: Int = bytes.size) : this(bytes, 0, State(forbiddenFrom), false)
    private class State(val forbiddenFrom: Int) { var inspected = 0; var committed = 0 }
    val inspected: Int get() = state.inspected
    val committed: Int get() = state.committed
    override fun exhausted() = index == bytes.size
    override fun readByte(): Byte {
        check(index < state.forbiddenFrom) { "Forbidden byte inspected at $index" }
        check(!exhausted()) { "Truncated input" }
        state.inspected = maxOf(state.inspected, index + 1)
        return bytes[index++].also { if (!isPeek) state.committed = index }
    }
    override fun readByteArray(nBytes: Int) = ByteArray(nBytes) { readByte() }
    override fun skip(nBytes: Long) { require(nBytes in 0..Int.MAX_VALUE); repeat(nBytes.toInt()) { readByte() } }
    override fun peek(): Source<ByteArraySink> = InspectingSource(bytes, index, state, true)
    override fun transferTo(sink: ByteArraySink): Long {
        var count = 0L
        while (!exhausted()) { sink.writeByte(readByte()); count++ }
        return count
    }
}

object IncrementalFixtures {
    val threeIntegers = byteArrayOf(0x30, 9, 2, 1, 1, 2, 1, 2, 2, 1, 3)
    val fourIntegers = byteArrayOf(0x30, 12, 2, 1, 1, 2, 1, 2, 2, 1, 3, 2, 1, 4)
    val childBeyondParent = byteArrayOf(0x30, 2, 2, 1, 1)
}
