package at.asitplus.awesn1

import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

val BitVectorTest by matrixSuite {

    "fixed vectors retain their exact logical extent" {
        val immutable = BitArray(BitVector.BitOrder.LSB0, false, false, true, false)
        val mutable = MutableBitArray(BitVector.BitOrder.LSB0, 9)

        immutable.logicalBitCount shouldBe 4L
        immutable.toList() shouldBe listOf(false, false, true, false)
        immutable.toLsb0ByteArray() shouldBe byteArrayOf(0x04)
        mutable.logicalBitCount shouldBe 9L
        mutable.toList() shouldBe List(9) { false }
        mutable.toLsb0ByteArray() shouldBe byteArrayOf(0, 0)
        mutable.nextSetBit(mutable.logicalBitCount) shouldBe -1
    }

    "fixed vectors reject indexes outside their domain" {
        val bits = MutableBitArray(BitVector.BitOrder.LSB0, 3)

        shouldThrow<IndexOutOfBoundsException> { bits[-1] }
        shouldThrow<IndexOutOfBoundsException> { bits[3] }
        shouldThrow<IndexOutOfBoundsException> { bits[3] = true }
    }

    "unbounded vectors accept unset indexes beyond their storage" {
        val bits = BitSet()

        bits[0] shouldBe false
        bits[Long.MAX_VALUE] shouldBe false
        shouldThrow<IndexOutOfBoundsException> { bits[-1] }
    }

    "LSB0 and MSB0 layouts preserve logical indexes" {
        val fixed = BitArray(BitVector.BitOrder.LSB0, true, false, true)
        val growing = BitSet(true, false, true)

        fixed.toLsb0ByteArray() shouldBe byteArrayOf(0x05)
        fixed.toMsb0ByteArray() shouldBe byteArrayOf(0xA0.toByte())
        fixed.lsb0ByteIterator().collectBytes() shouldBe byteArrayOf(0x05)
        fixed.msb0ByteIterator().collectBytes() shouldBe byteArrayOf(0xA0.toByte())
        growing.lsb0ByteIterator().collectBytes() shouldBe byteArrayOf(0x05)
        growing.msb0ByteIterator().collectBytes() shouldBe byteArrayOf(0xA0.toByte())
        byteArrayOf(0x01).getLsb0Bit(0) shouldBe true
        byteArrayOf(0x80.toByte()).getMsb0Bit(0) shouldBe true
        byteArrayOf(0x01).getMsb0Bit(7) shouldBe true
        byteArrayOf(0x80.toByte()).getMsb0Bit(8) shouldBe false
        shouldThrow<IndexOutOfBoundsException> { byteArrayOf(0).getMsb0Bit(-1) }
    }

    "array-backed types expose their native order" {
        val lsb0 = MutableBitArray(BitVector.BitOrder.LSB0, 3)
        val msb0 = MutableBitArray(BitVector.BitOrder.MSB0, 3)
        val wrapped = BitArray.wrap(BitVector.BitOrder.MSB0, byteArrayOf(0xA0.toByte()), logicalBitCount = 3)
        lsb0[0] = true
        msb0[0] = true

        (lsb0 is MutableLsb0BitArray) shouldBe true
        (msb0 is MutableMsb0BitArray) shouldBe true
        lsb0.bitOrder shouldBe BitVector.BitOrder.LSB0
        msb0.bitOrder shouldBe BitVector.BitOrder.MSB0
        lsb0.toLsb0ByteArray() shouldBe byteArrayOf(0x01)
        msb0.toMsb0ByteArray() shouldBe byteArrayOf(0x80.toByte())
        lsb0.toLogicalBitString() shouldBe msb0.toLogicalBitString()
        (wrapped is Msb0BitArray) shouldBe true
        wrapped.toLogicalBitString() shouldBe "101"
        shouldThrow<IndexOutOfBoundsException> { wrapped[3] }
        Asn1BitString(false).bitOrder shouldBe BitVector.BitOrder.MSB0
    }

    "oriented factories return real BitArray subclasses" {
        val readOnlyMsb = Msb0BitArray(byteArrayOf(0xA0.toByte()), logicalBitCount = 3)
        val readOnlyLsb = Lsb0BitArray(byteArrayOf(0x05), logicalBitCount = 3)
        val mutableMsb = MutableMsb0BitArray(byteArrayOf(0xA0.toByte()), logicalBitCount = 3)
        val mutableLsb = MutableLsb0BitArray(byteArrayOf(0x05), logicalBitCount = 3)
        val mutableMsbAsMutable: MutableBitArray = mutableMsb
        val mutableMsbAsReadOnly: BitArray = mutableMsb
        val mutableLsbAsMutable: MutableBitArray = mutableLsb
        val mutableLsbAsReadOnly: BitArray = mutableLsb

        (readOnlyMsb is BitArray) shouldBe true
        (readOnlyLsb is BitArray) shouldBe true
        (mutableMsbAsMutable === mutableMsbAsReadOnly) shouldBe true
        (mutableLsbAsMutable === mutableLsbAsReadOnly) shouldBe true
    }

    "read-only arrays copy naturally to independent mutable arrays" {
        val readOnly = BitArray(BitVector.BitOrder.MSB0, true, false, true)
        val mutable = readOnly.toMutableBitArray()

        mutable shouldBe readOnly
        readOnly shouldBe mutable
        mutable.bitOrder shouldBe BitVector.BitOrder.MSB0
        (mutable is MutableMsb0BitArray) shouldBe true

        mutable[0] = false
        readOnly[0] shouldBe true
        mutable[0] shouldBe false
    }

    "copying and wrapping preserve extent and ownership" {
        val copiedSource = byteArrayOf(0xFF.toByte())
        val copied = BitArray(BitVector.BitOrder.LSB0, copiedSource, logicalBitCount = 3)
        copiedSource[0] = 0

        copied.logicalBitCount shouldBe 3L
        copied.toLogicalBitString() shouldBe "111"

        val wrappedSource = byteArrayOf(0)
        val wrapped = MutableLsb0BitArray.wrap(wrappedSource, logicalBitCount = 3)
        wrapped[1] = true
        wrappedSource shouldBe byteArrayOf(0x02)
    }

    "ASN.1 BIT STRING is an exact bounded logical vector" {
        val value = Asn1BitString(true, false, true)
        val bounded: FixedSizeBitVector = value

        value.logicalBitCount shouldBe 3L
        value.toList() shouldBe listOf(true, false, true)
        value.highestSetIndex() shouldBe 2
        value.nextSetBit(1) shouldBe 2
        value.nextSetBit(3) shouldBe -1
        bounded.toMsb0ByteArray() shouldBe byteArrayOf(0xA0.toByte())
        bounded.toLsb0ByteArray() shouldBe byteArrayOf(0x05)
        bounded.msb0ByteIterator().collectBytes() shouldBe byteArrayOf(0xA0.toByte())
        bounded.lsb0ByteIterator().collectBytes() shouldBe byteArrayOf(0x05)
        shouldThrow<IndexOutOfBoundsException> { value[3] }
    }

    "bounded byte representations clear non-logical padding" {
        val msb0: FixedSizeBitVector =
            BitArray.wrap(BitVector.BitOrder.MSB0, byteArrayOf(0xBF.toByte()), logicalBitCount = 3)
        val lsb0: FixedSizeBitVector =
            BitArray.wrap(BitVector.BitOrder.LSB0, byteArrayOf(0xFF.toByte()), logicalBitCount = 3)

        msb0.toMsb0ByteArray() shouldBe byteArrayOf(0xA0.toByte())
        msb0.toLsb0ByteArray() shouldBe byteArrayOf(0x05)
        msb0.msb0ByteIterator().collectBytes() shouldBe byteArrayOf(0xA0.toByte())
        msb0.lsb0ByteIterator().collectBytes() shouldBe byteArrayOf(0x05)
        lsb0.toLsb0ByteArray() shouldBe byteArrayOf(0x07)
        lsb0.toMsb0ByteArray() shouldBe byteArrayOf(0xE0.toByte())
    }

    "ASN.1 conversion preserves bounded zeroes and compacts unbounded zeroes" {
        val bounded = Asn1BitString(BitArray(BitVector.BitOrder.MSB0, false, false, true, false))
        val unbounded = Asn1BitString(BitSet(false, false, true, false))

        bounded.logicalBitCount shouldBe 4L
        bounded.numPaddingBits shouldBe 4.toByte()
        bounded.toList() shouldBe listOf(false, false, true, false)
        Asn1.BitString(BitArray(BitVector.BitOrder.LSB0, false, false, true, false)).content shouldBe byteArrayOf(4, 0x20)
        unbounded.logicalBitCount shouldBe 3L
        unbounded.numPaddingBits shouldBe 5.toByte()
        unbounded.toList() shouldBe listOf(false, false, true)
    }
}

private fun ByteIterator.collectBytes(): ByteArray {
    val bytes = mutableListOf<Byte>()
    while (hasNext()) bytes.add(nextByte())
    return bytes.toByteArray()
}
