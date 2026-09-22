// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

val BitVectorComprehensiveTest by matrixSuite {

    "bounded implementations agree with the logical reference model" {
        val sizes = listOf(0, 1, 2, 7, 8, 9, 15, 16, 17, 31, 32, 33)

        for (size in sizes) {
            val expected = List(size) { index -> index % 3 == 0 || index == size - 1 }
            for (order in BitVector.BitOrder.entries) {
                val immutable: FixedSizeBitVector = BitArray(order, size) { expected[it] }
                val mutable: FixedSizeBitVector = MutableBitArray(order, size) { expected[it] }

                for (actual in listOf(immutable, mutable)) {
                    actual.logicalBitCount shouldBe size.toLong()
                    actual.toList() shouldBe expected
                    actual.toLogicalBitString() shouldBe expected.logicalString()
                    actual.highestSetIndex() shouldBe expected.highestSetIndex()
                    actual.toLsb0ByteArray() shouldBe expected.pack(BitVector.BitOrder.LSB0)
                    actual.toMsb0ByteArray() shouldBe expected.pack(BitVector.BitOrder.MSB0)
                    actual.lsb0ByteIterator().drainBytes() shouldBe expected.pack(BitVector.BitOrder.LSB0)
                    actual.msb0ByteIterator().drainBytes() shouldBe expected.pack(BitVector.BitOrder.MSB0)

                    for (fromIndex in 0L..size.toLong()) {
                        actual.nextSetBit(fromIndex) shouldBe expected.nextSetBit(fromIndex)
                    }
                }
            }
        }
    }

    "all small bit patterns round-trip through both byte orders" {
        for (size in 0..9) {
            repeat(1 shl size) { pattern ->
                val expected = List(size) { index -> pattern and (1 shl index) != 0 }
                for (order in BitVector.BitOrder.entries) {
                    val original = BitArray(order, size) { expected[it] }
                    val bytes = when (order) {
                        BitVector.BitOrder.LSB0 -> original.toLsb0ByteArray()
                        BitVector.BitOrder.MSB0 -> original.toMsb0ByteArray()
                    }
                    val roundTrip = BitArray.wrap(order, bytes, size.toLong())

                    roundTrip.toList() shouldBe expected
                    roundTrip.toLogicalBitString() shouldBe expected.logicalString()
                }
            }
        }
    }

    "bounded iterators include trailing false bits and obey Iterator exhaustion" {
        val bits: FixedSizeBitVector = BitArray(BitVector.BitOrder.MSB0, true, false, false)
        val bitIterator = bits.iterator()
        val byteIterator = bits.msb0ByteIterator()

        bitIterator.next() shouldBe true
        bitIterator.next() shouldBe false
        bitIterator.next() shouldBe false
        bitIterator.hasNext() shouldBe false
        shouldThrow<NoSuchElementException> { bitIterator.next() }

        byteIterator.nextByte() shouldBe 0x80.toByte()
        byteIterator.hasNext() shouldBe false
        shouldThrow<NoSuchElementException> { byteIterator.nextByte() }

        val empty = BitArray(BitVector.BitOrder.LSB0)
        empty.iterator().hasNext() shouldBe false
        empty.lsb0ByteIterator().hasNext() shouldBe false
        shouldThrow<NoSuchElementException> { empty.iterator().next() }
        shouldThrow<NoSuchElementException> { empty.lsb0ByteIterator().nextByte() }
    }

    "mutable bounded operations preserve extent in both orientations" {
        for (order in BitVector.BitOrder.entries) {
            val bits = MutableBitArray(order, 17)

            bits.set(0L, 8L)
            bits.clear(1L, 7L)
            bits.flip(8L, 16L)
            bits.flip(4)
            bits.set(7)
            bits.clear(7)

            bits.logicalBitCount shouldBe 17L
            bits.toLogicalBitString() shouldBe "10001000011111111"
            bits.highestSetIndex() shouldBe 16L
            bits.nextSetBit(1) shouldBe 4L
            shouldThrow<IndexOutOfBoundsException> { bits[-1] = true }
            shouldThrow<IndexOutOfBoundsException> { bits[17] = true }
            shouldThrow<IndexOutOfBoundsException> { bits[-1] }
            shouldThrow<IndexOutOfBoundsException> { bits[17] }
            shouldThrow<IndexOutOfBoundsException> { bits.nextSetBit(-1) }
        }
    }

    "wrapping aliases input while copying constructors and byte outputs do not" {
        for (order in BitVector.BitOrder.entries) {
            val source = byteArrayOf(0)
            val wrapped = BitArray.wrap(order, source)
            val copied = BitArray(order, source)
            val mutableCopied = source.toBitArray(order)

            source[0] = if (order == BitVector.BitOrder.LSB0) 0x01 else 0x80.toByte()

            wrapped[0] shouldBe true
            copied[0] shouldBe false
            mutableCopied[0] shouldBe false

            val exported = wrapped.toLsb0ByteArray()
            exported[0] = 0
            wrapped[0] shouldBe true
        }
    }

    "array equality respects orientation and ignores non-logical padding" {
        val msb = BitArray.wrap(BitVector.BitOrder.MSB0, byteArrayOf(0xBF.toByte()), 3)
        val sameMsb = BitArray.wrap(BitVector.BitOrder.MSB0, byteArrayOf(0xA0.toByte()), 3)
        val lsb = BitArray.wrap(BitVector.BitOrder.LSB0, byteArrayOf(0xFD.toByte()), 3)
        val differentExtent = BitArray(BitVector.BitOrder.MSB0, true, false, true, false)

        msb shouldBe sameMsb
        msb.hashCode() shouldBe sameMsb.hashCode()
        msb shouldNotBe lsb
        msb.hashCode() shouldNotBe lsb.hashCode()
        (msb == differentExtent) shouldBe false
        msb.msb0ByteIterator().drainBytes() shouldBe byteArrayOf(0xA0.toByte())
        lsb.lsb0ByteIterator().drainBytes() shouldBe byteArrayOf(0x05)

        val mutableMsb = MutableBitArray.wrap(BitVector.BitOrder.MSB0, byteArrayOf(0xBF.toByte()), 3)
        val mutableLsb = MutableBitArray.wrap(BitVector.BitOrder.LSB0, byteArrayOf(0xFD.toByte()), 3)
        mutableMsb shouldNotBe mutableLsb
        mutableMsb.hashCode() shouldNotBe mutableLsb.hashCode()
        mutableMsb.toMsb0ByteArray() shouldBe byteArrayOf(0xA0.toByte())
        mutableMsb.toLsb0ByteArray() shouldBe byteArrayOf(0x05)
        mutableLsb.msb0ByteIterator().drainBytes() shouldBe byteArrayOf(0xA0.toByte())
        mutableLsb.lsb0ByteIterator().drainBytes() shouldBe byteArrayOf(0x05)
    }

    "bit array factories validate size and logical strings" {
        for (order in BitVector.BitOrder.entries) {
            BitArray.fromLogicalBitString("00101", order).toLogicalBitString() shouldBe "00101"
            MutableBitArray.fromLogicalBitString("00101", order).toLogicalBitString() shouldBe "00101"
            BitArray.fromLogicalBitString("", order).logicalBitCount shouldBe 0L
            MutableBitArray.fromLogicalBitString("", order).logicalBitCount shouldBe 0L
            BitArray.fromLogicalBitStringOrNull("10x", order) shouldBe null
            MutableBitArray.fromLogicalBitStringOrNull("10x", order) shouldBe null
            shouldThrow<IllegalArgumentException> { BitArray.fromLogicalBitString("10x", order) }
            shouldThrow<IllegalArgumentException> { MutableBitArray.fromLogicalBitString("10x", order) }
            shouldThrow<IllegalArgumentException> { MutableBitArray(order, -1) }
            shouldThrow<IllegalArgumentException> { BitArray.wrap(order, byteArrayOf(0), 0) }
            shouldThrow<IllegalArgumentException> { MutableBitArray.wrap(order, byteArrayOf(0), 9) }
        }
    }

    "BitSet grows and compacts according to its highest set bit" {
        val bits: MutableUnboundedCompactingBitVector = BitSet()

        for (index in listOf(0L, 7L, 8L, 15L, 16L, 63L)) bits[index] = true
        bits.highestSetIndex() shouldBe 63L
        bits.toLogicalBitString().length shouldBe 64
        bits.toLsb0ByteArray().size shouldBe 8
        bits.toMsb0ByteArray() shouldBe bits.toLsb0ByteArray().map(Byte::reverseBits).toByteArray()

        for (index in listOf(63L, 16L, 15L, 8L, 7L, 0L)) {
            bits[index] = false
        }
        bits.highestSetIndex() shouldBe -1L
        bits.toLogicalBitString() shouldBe ""
        bits.toLsb0ByteArray() shouldBe byteArrayOf()
        bits.iterator().hasNext() shouldBe false

        bits[1_000] = false
        bits.highestSetIndex() shouldBe -1L
        bits.nextSetBitAfter(Long.MAX_VALUE) shouldBe -1L
        shouldThrow<IndexOutOfBoundsException> { bits.nextSetBit(-1) }
        shouldThrow<IndexOutOfBoundsException> { bits[-1] = true }
    }

    "BitSet bulk mutation and byte iterators maintain compact state" {
        val bits = BitSet()

        shouldThrow<IllegalStateException> {
            bits.mutateLsb0Bytes {
                add(0x04)
                add(0)
                error("stop")
            }
        }
        bits.toLsb0ByteArray() shouldBe byteArrayOf(0x04)
        bits.toLogicalBitString() shouldBe "001"

        val iterator = bits.lsb0ByteIterator()
        bits[8] = true
        shouldThrow<ConcurrentModificationException> { iterator.hasNext() }
        bits.lsb0ByteIterator().drainBytes() shouldBe byteArrayOf(0x04, 0x01)
        bits.msb0ByteIterator().drainBytes() shouldBe byteArrayOf(0x20, 0x80.toByte())
    }

    "BitSet constructors copy bytes and logical strings are compact" {
        val source = byteArrayOf(0x05, 0)
        val bits = BitSet(source)
        source[0] = 0

        bits.toLogicalBitString() shouldBe "101"
        bits.toLsb0ByteArray() shouldBe byteArrayOf(0x05)
        BitSet.fromLogicalBitString("101000").toLogicalBitString() shouldBe "101"
        BitSet.fromLogicalBitString("").toLogicalBitString() shouldBe ""
        BitSet.fromLogicalBitStringOrNull("10x") shouldBe null
        shouldThrow<IllegalArgumentException> { BitSet.fromLogicalBitString("10x") }
    }

    "ASN.1 BIT STRING delegates every bounded operation to its live MSB0 view" {
        val source = byteArrayOf(0x80.toByte(), 0x01)
        val value = Asn1BitString(source)
        val bounded: FixedSizeBitVector = value

        bounded.logicalBitCount shouldBe 16L
        bounded.toLogicalBitString() shouldBe "1000000000000001"
        bounded.toMsb0ByteArray() shouldBe byteArrayOf(0x80.toByte(), 0x01)
        bounded.toLsb0ByteArray() shouldBe byteArrayOf(0x01, 0x80.toByte())
        bounded.msb0ByteIterator().drainBytes() shouldBe bounded.toMsb0ByteArray()
        bounded.lsb0ByteIterator().drainBytes() shouldBe bounded.toLsb0ByteArray()
        bounded.highestSetIndex() shouldBe 15L
        bounded.nextSetBit(1) shouldBe 15L

        source[0] = 0x40
        bounded.toLogicalBitString() shouldBe "0100000000000001"
        bounded.nextSetBit(0) shouldBe 1L
    }

    "ASN.1 conversions preserve bounded extent and compact unbounded extent" {
        for (size in listOf(0, 1, 7, 8, 9, 16, 17)) {
            val expected = List(size) { index -> index == 0 || index == size / 2 }
            val boundedSource = BitArray(BitVector.BitOrder.LSB0, size) { expected[it] }
            val bounded = Asn1BitString(boundedSource)
            val unbounded = Asn1BitString(BitSet(size) { expected[it] })

            bounded.logicalBitCount shouldBe size.toLong()
            bounded.toList() shouldBe expected
            bounded.numPaddingBits shouldBe ((8 - size % 8) % 8).toByte()
            bounded.toMsb0ByteArray() shouldBe expected.pack(BitVector.BitOrder.MSB0)

            val highest = expected.indexOfLast { it }
            unbounded.logicalBitCount shouldBe (highest + 1).toLong()
            unbounded.toList() shouldBe expected.take(highest + 1)
            bounded.toBitSet().toLogicalBitString() shouldBe expected.take(highest + 1).logicalString()
        }
    }

    "byte helpers cover every byte value and reject negative indexes" {
        for (value in 0..255) {
            val byte = value.toByte()
            byte.reverseBits().reverseBits() shouldBe byte
            for (index in 0L..7L) {
                byteArrayOf(byte).getLsb0Bit(index) shouldBe (value and (1 shl index.toInt()) != 0)
                byteArrayOf(byte).getMsb0Bit(index) shouldBe (value and (0x80 ushr index.toInt()) != 0)
            }
        }

        byteArrayOf(1).getLsb0Bit(Long.MAX_VALUE) shouldBe false
        byteArrayOf(1).getMsb0Bit(Long.MAX_VALUE) shouldBe false
        shouldThrow<IndexOutOfBoundsException> { byteArrayOf().getLsb0Bit(-1) }
        shouldThrow<IndexOutOfBoundsException> { byteArrayOf().getMsb0Bit(-1) }
    }
}

private fun List<Boolean>.pack(order: BitVector.BitOrder): ByteArray =
    ByteArray((size + 7) / 8).also { bytes ->
        forEachIndexed { index, bit ->
            if (bit) {
                val mask = when (order) {
                    BitVector.BitOrder.LSB0 -> 1 shl (index % 8)
                    BitVector.BitOrder.MSB0 -> 0x80 ushr (index % 8)
                }
                bytes[index / 8] = (bytes[index / 8].toInt() or mask).toByte()
            }
        }
    }

private fun List<Boolean>.logicalString(): String = joinToString("") { if (it) "1" else "0" }

private fun List<Boolean>.highestSetIndex(): Long = indexOfLast { it }.toLong()

private fun List<Boolean>.nextSetBit(fromIndex: Long): Long {
    for (index in fromIndex.toInt() until size) if (this[index]) return index.toLong()
    return -1
}

private fun ByteIterator.drainBytes(): ByteArray {
    val bytes = mutableListOf<Byte>()
    while (hasNext()) bytes.add(nextByte())
    return bytes.toByteArray()
}
