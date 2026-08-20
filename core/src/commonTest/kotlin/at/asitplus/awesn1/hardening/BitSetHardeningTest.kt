package at.asitplus.awesn1.hardening

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.BitSet
import at.asitplus.awesn1.encoding.encodeToDer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

val BitSetCompactionHardeningTest by matrixSuite {

    // a bit count whose byte index exceeds Int.MAX_VALUE must be rejected loudly
    // not silently truncated to a bogus/negative byte index
    "BitSet(nBits) rejects a byte index beyond Int range instead of truncating" {
        val overflowingNBits = (Int.MAX_VALUE.toLong() + 1) * 8 // /8 == Int.MAX_VALUE + 1 -> not Int-representable
        shouldThrow<Asn1Exception> { BitSet(overflowingNBits) }
    }

    "BitSet(nBits) rejects the exact preallocate overflow boundary" {
        shouldThrow<Asn1Exception> { BitSet(Int.MAX_VALUE.toLong() * 8) }
    }

    "preallocated all-zero BitSet has empty semantic representation" {
        val bits = BitSet(128)
        var visited = 0
        bits.forEachIndexed { _, _ -> visited++ }

        bits.mutableBytes.toByteArray() shouldBe byteArrayOf()
        bits.toByteArray() shouldBe byteArrayOf()
        bits.toBitStringView() shouldBe ""
        bits.memDumpView() shouldBe ""
        bits.copyOf().toByteArray() shouldBe byteArrayOf()
        bits.iterator().hasNext() shouldBe false
        visited shouldBe 0
    }

    "trailing zero backing bytes are removed from public byte views" {
        val bits = BitSet(byteArrayOf(0x04, 0x00, 0x00))

        bits.mutableBytes.toByteArray() shouldBe byteArrayOf(0x04)
        bits.toByteArray() shouldBe byteArrayOf(0x04)
        bits.copyOf().toByteArray() shouldBe byteArrayOf(0x04)
        bits.toBitStringView() shouldBe "001"
        bits.memDumpView() shouldBe "00000100"
        bits.nextSetBit(0) shouldBe 2
        bits.nextSetBit(2) shouldBe 2
        bits.nextSetBitAfter(2) shouldBe -1
        bits.nextSetBit(3) shouldBe -1
    }

    "Asn1BitString from preallocated BitSet does not encode backing zero bytes" {
        val empty = Asn1BitString(BitSet(64))
        val sparse = Asn1BitString(BitSet(64).also { it[2] = true })

        empty.numPaddingBits shouldBe 0
        empty.bitCarryingBytes shouldBe byteArrayOf()
        empty.encodeToDer() shouldBe "030100".hexToByteArray(HexFormat.UpperCase)

        sparse.numPaddingBits shouldBe 5
        sparse.bitCarryingBytes shouldBe byteArrayOf(0x20)
        sparse.encodeToDer() shouldBe "03020520".hexToByteArray(HexFormat.UpperCase)
    }

    "BitSet equality compares both directions and hash uses compact content" {
        val empty = BitSet()
        val nonEmpty = BitSet.fromString("1")
        val padded = BitSet(byteArrayOf(0x04, 0x00, 0x00))
        val compact = BitSet.fromString("001")

        empty shouldNotBe nonEmpty
        nonEmpty shouldNotBe empty
        padded shouldBe compact
        padded.hashCode() shouldBe compact.hashCode()
    }

    "nextSetBit searches inclusively from fromIndex" {
        val bits = BitSet().also {
            it[0] = true
            it[7] = true
            it[8] = true
            it[15] = true
            it[16] = true
        }

        bits.nextSetBit(0) shouldBe 0
        bits.nextSetBitAfter(0) shouldBe 7
        bits.nextSetBit(1) shouldBe 7
        bits.nextSetBitAfter(1) shouldBe 7
        bits.nextSetBit(7) shouldBe 7
        bits.nextSetBitAfter(7) shouldBe 8
        bits.nextSetBit(8) shouldBe 8
        bits.nextSetBitAfter(8) shouldBe 15
        bits.nextSetBit(9) shouldBe 15
        bits.nextSetBit(15) shouldBe 15
        bits.nextSetBitAfter(15) shouldBe 16
        bits.nextSetBit(16) shouldBe 16
        bits.nextSetBitAfter(16) shouldBe -1
        bits.nextSetBit(17) shouldBe -1
    }

    "initializer factory does not create a bogus final bit" - {
        "all false" {
            val bits = BitSet(8) { false }

            bits.toByteArray() shouldBe byteArrayOf()
            bits.toBitStringView() shouldBe ""
        }

        "last false" {
            val bits = BitSet(8) { it == 2 }

            bits.toByteArray() shouldBe byteArrayOf(0x04)
            bits.toBitStringView() shouldBe "001"
        }
    }
}
