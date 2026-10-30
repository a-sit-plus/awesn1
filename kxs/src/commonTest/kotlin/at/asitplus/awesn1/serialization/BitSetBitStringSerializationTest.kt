package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.BitSet
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.json.Json

@OptIn(ExperimentalStdlibApi::class)
val BitSetBitStringSerializationTest by matrixSuite {

    "top-level BitSet and Asn1BitString share DER BIT STRING encoding" {
        val bitSet = BitSet.fromString("001")
        val bitString = Asn1BitString(bitSet)

        DER.encodeToByteArray(bitSet).toHexString() shouldBe "03020520"
        DER.encodeToByteArray(bitString).toHexString() shouldBe "03020520"

        DER.decodeFromByteArray<BitSet>("03020520".hexToByteArray()) shouldBe bitSet
        DER.decodeFromByteArray<Asn1BitString.NamedBitList>("03020520".hexToByteArray()) shouldBe bitString
    }

    "top-level BitSet and Asn1BitString share non-DER string encoding" {
        val bitSet = BitSet.fromString("001")
        val bitString = Asn1BitString(bitSet)

        val setEncoded = Json.encodeToString(bitSet)
        Json.encodeToString(bitString) shouldBe setEncoded

        Json.decodeFromString<Asn1BitString.NamedBitList>(setEncoded) shouldBe bitString
        Json.decodeFromString<BitSet>(setEncoded) shouldBe bitSet
    }

    "top-level BitSet DER decoding" {
        DER.decodeFromByteArray<BitSet>("0302030f".hexToByteArray()).let {
            it[3] shouldBe false
            it[4] shouldBe true
            it[5] shouldBe false
            it[6] shouldBe false
            it[7] shouldBe false
        }
    }

    "top-level empty BitSet and Asn1BitString share encodings" {
        val bitSet = BitSet()
        val bitString = Asn1BitString(bitSet)

        DER.encodeToByteArray(bitSet).toHexString() shouldBe "030100"
        DER.encodeToByteArray(bitString).toHexString() shouldBe "030100"

        Json.encodeToString(bitSet) shouldBe Json.encodeToString(bitString)
    }
}
