package at.asitplus.awesn1

import at.asitplus.awesn1.encoding.decodeFromDer
import at.asitplus.awesn1.encoding.encodeToDer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

val Asn1BitStringTest by matrixSuite {

    val bitSet1 = BitSet.fromString("011011100101110111")
    val bitSet2 = BitSet.fromString("011011100101110111")
    val bitSet3 = BitSet.fromString("011011100101110101")

    "Bit String Test" {
        val fromBitSet1 = Asn1BitString.fromBitSet(bitSet1)
        val fromBitSet2 = Asn1BitString.fromBitSet(bitSet2)
        val fromBitSet3 = Asn1BitString.fromBitSet(bitSet3)
        fromBitSet1 shouldBe fromBitSet1
        fromBitSet1 shouldBe fromBitSet2
        fromBitSet1 shouldNotBe fromBitSet3
        fromBitSet1.hashCode() shouldBe fromBitSet1.hashCode()
        fromBitSet1.hashCode() shouldBe fromBitSet2.hashCode()
        fromBitSet1.hashCode() shouldNotBe fromBitSet3.hashCode()
    }

    "Bit String Test 2" {
        val bitString = Asn1BitString.fromNamedBits(false, true)
        bitString.highestSetIndex shouldBe 1
        bitString.numPaddingBits shouldBe 6
        val encoded = bitString.encodeToDer()
        val decoded = Asn1BitString.NamedBitList.decodeFromDer(encoded)
        decoded shouldBe bitString
        decoded.numPaddingBits shouldBe 6
        shouldThrow<IndexOutOfBoundsException> { decoded[-1] }
        decoded[0] shouldBe false
        decoded[1] shouldBe true
        decoded[2] shouldBe false
    }

    "Bit String Test 3" {
        val bitString = Asn1BitString.General.fromBits(false, true, false, true, false, false, false, true, false)
        bitString.numPaddingBits shouldBe 7
        bitString.sizeBytes shouldBe 2
        bitString.sizeBits shouldBe 9
        bitString[8] shouldBe false
        bitString[7] shouldBe true
        shouldThrow<IndexOutOfBoundsException> { bitString[9] }
    }

    "Construction from ByteArray" {
        Asn1BitString.fromByteArray(byteArrayOf(), numPaddingBits = 0).let {
            it.sizeBits shouldBe 0L
            it.sizeBytes shouldBe 0
            it.numPaddingBits shouldBe 0
            it.bitCarryingBytes.shouldBeEmpty()
            shouldThrow<IndexOutOfBoundsException> { it[0] }
        }
        shouldThrow<Asn1Exception> { Asn1BitString.fromByteArray(byteArrayOf(), numPaddingBits = 3) }
        shouldThrow<Asn1Exception> { Asn1BitString.fromByteArray(byteArrayOf(0x10), numPaddingBits = 5) }
        Asn1BitString.fromByteArray(byteArrayOf(0x10), numPaddingBits = 4).let {
            it.sizeBits shouldBe 4L
            it.sizeBytes shouldBe 1
            it.numPaddingBits shouldBe 4
            it.bitCarryingBytes shouldBe byteArrayOf(0x10)
        }
    }

    "Malformed DER round-trips" {
        val valid = Asn1BitString.fromByteArray(byteArrayOf(0x10), numPaddingBits = 4)
        val invalid = valid.encodeToDer().also { it[it.lastIndex] = 0x11 }.let { Asn1BitString.decodeFromDer(it) }
        valid shouldBe invalid
        valid.encodeToDer() shouldNotBe invalid.encodeToDer()
        shouldThrow<IndexOutOfBoundsException> { valid[7] }
        valid.bitCarryingBytes shouldBe invalid.bitCarryingBytes
    }

    "Malformed DER round-trips for NamedBitSet" {
        val valid = Asn1BitString.fromNamedBits(false, false, true)
        val invalid = valid.encodeToDer().also { it[it.lastIndex] = 0x3f }.let { Asn1BitString.NamedBitList.decodeFromDer(it) }
        valid shouldBe invalid
        valid.encodeToDer() shouldNotBe invalid.encodeToDer()
        invalid[4] shouldBe false
        valid.bitCarryingBytes shouldBe invalid.bitCarryingBytes
    }

    "AI-suggested regression tests" {
        fun general(hexString: String, block: Asn1BitString.General.()->Unit = {}) = Asn1BitString.General.decodeFromDer(hexString.hexToByteArray()).also(block)
        fun namedBitList(hexString: String, block: Asn1BitString.NamedBitList.()->Unit = {}) = Asn1BitString.NamedBitList.decodeFromDer(hexString.hexToByteArray()).also(block)
        general("03 02 07 80") { shouldThrow<IndexOutOfBoundsException> { get(1) }}
        general("03 02 07 80") { sizeBits shouldBe 1 }
        namedBitList("03 03 00 80 01") { get(15) shouldBe true }
        namedBitList("03 01 00") { bitCarryingBytes.shouldBeEmpty() }
        // the trailing 1 is masked out (permissive parsing) since it is marked as padding
        namedBitList("03 02 07 81") { get(7) shouldBe false }
        // permissive equality
        namedBitList("03 01 00") shouldBe namedBitList("03 01 07")
        Asn1BitString.fromNamedBits().encodeToTlv().content shouldBe byteArrayOf(0x00)
        BitSet(16).also { it[0] = true; it[15] = true}.let(Asn1BitString::fromBitSet).encodeToTlv().content shouldBe byteArrayOf(0x00, 0x80.toByte(), 0x01)
    }
}