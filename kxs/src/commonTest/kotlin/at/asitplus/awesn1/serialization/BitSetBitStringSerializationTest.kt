package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.BitSet
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.SerializationException
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.json.Json

@OptIn(ExperimentalStdlibApi::class)
val BitSetBitStringSerializationTest by testSuite {

    "top-level BitSet and Asn1BitString share DER BIT STRING encoding" {
        val bitSet = BitSet.fromString("001")
        val bitString = Asn1BitString(bitSet)

        DER.encodeToByteArray(bitSet).toHexString() shouldBe "03020520"
        DER.encodeToByteArray(bitString).toHexString() shouldBe "03020520"

        DER.decodeFromByteArray<BitSet>("03020520".hexToByteArray()) shouldBe bitSet
        DER.decodeFromByteArray<Asn1BitString>("03020520".hexToByteArray()) shouldBe bitString
    }

    "top-level BitSet and Asn1BitString share non-DER string encoding" {
        val bitSet = BitSet.fromString("001")
        val bitString = Asn1BitString(bitSet)

        Json.encodeToString(BitSet.serializer(), bitSet) shouldBe """"5:IA==""""
        Json.encodeToString(Asn1BitString.serializer(), bitString) shouldBe """"5:IA==""""

        Json.decodeFromString(BitSet.serializer(), """"5:IA=="""") shouldBe bitSet
        Json.decodeFromString(Asn1BitString.serializer(), """"5:IA=="""") shouldBe bitString
    }

    "top-level BitSet DER decoding uses strict Asn1BitString validation" {
        shouldThrow<SerializationException> {
            DER.decodeFromByteArray<BitSet>("03020301".hexToByteArray())
        }
    }

    "top-level empty BitSet and Asn1BitString share encodings" {
        val bitSet = BitSet()
        val bitString = Asn1BitString(bitSet)

        DER.encodeToByteArray(bitSet).toHexString() shouldBe "030100"
        DER.encodeToByteArray(bitString).toHexString() shouldBe "030100"

        Json.encodeToString(BitSet.serializer(), bitSet) shouldBe """"0:""""
        Json.encodeToString(Asn1BitString.serializer(), bitString) shouldBe """"0:""""
    }
}
