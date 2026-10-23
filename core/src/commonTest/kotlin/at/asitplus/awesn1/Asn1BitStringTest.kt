package at.asitplus.awesn1

import at.asitplus.awesn1.encoding.decodeFromDer
import at.asitplus.awesn1.encoding.encodeToDer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

val Asn1BitStringTest by matrixSuite {

    val bitSet1 = BitSet.fromLogicalBitString("011011100101110111")
    val bitSet2 = BitSet.fromLogicalBitString("011011100101110111")
    val bitSet3 = BitSet.fromLogicalBitString("011011100101110101")

    "Bit String Test" {
        val fromBitSet1 = Asn1BitString(bitSet1)
        val fromBitSet2 = Asn1BitString(bitSet2)
        val fromBitSet3 = Asn1BitString(bitSet3)
        fromBitSet1 shouldBe fromBitSet1
        fromBitSet1 shouldBe fromBitSet2
        fromBitSet1 shouldNotBe fromBitSet3
        fromBitSet1.hashCode() shouldBe fromBitSet1.hashCode()
        fromBitSet1.hashCode() shouldBe fromBitSet2.hashCode()
        fromBitSet1.hashCode() shouldNotBe fromBitSet3.hashCode()
    }

    "Bit String Test 2" {
        val bitString = Asn1BitString(false)
        bitString.numPaddingBits shouldBe 7.toByte()
        val encoded = bitString.encodeToDer()
        val decoded = Asn1BitString.decodeFromDer(encoded)
        decoded.numPaddingBits shouldBe 7.toByte()
        decoded[0] shouldBe false
        shouldThrow<IndexOutOfBoundsException> { decoded[1] }
    }
}
