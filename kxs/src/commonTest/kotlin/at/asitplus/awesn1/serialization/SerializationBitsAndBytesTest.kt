package at.asitplus.awesn1.serialization

import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.matrixConfig
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlinx.serialization.*
import kotlin.jvm.JvmInline
import at.asitplus.awesn1.Asn1AbstractBitString as Asn1BitStringValue

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestBitsAndBytes by matrixSuite(
    matrixConfig { execution= ExecutionMode.Sequential }
) {
    "Bits and Bytes" - {
        "Bit string" {
            val empty = byteArrayOf()
            val valueClassEmpty = BitSetValue(empty)
            val valueClass = BitSetValue(byteArrayOf(1, 2, 3))

            DER.decodeFromByteArray<BitSetValue>(
                DER.encodeToByteArray(valueClassEmpty).also { it.toHexString() shouldBe "030100" }
            ).bytes shouldBe valueClassEmpty.bytes

            DER.decodeFromByteArray<BitSetValue>(
                DER.encodeToByteArray(valueClass)
                    .also { it.toHexString() shouldBe "030400010203" }
            ).bytes shouldBe valueClass.bytes

            shouldThrow<SerializationException> {
                DER.decodeFromHexString<BitSetValue>("030401010202" )
            }.message shouldContain "must not have padding bits"

            DER.decodeFromHexString<Asn1BitStringValue>("03020105").bitCarryingBytes shouldBe byteArrayOf(0x04)

            val tagged = BitSetValueTagged(byteArrayOf(0x01, 0x02))
            DER.decodeFromByteArray<BitSetValueTagged>(
                DER.encodeToByteArray(tagged)
            ).bytes.toList() shouldBe tagged.bytes.toList()
        }

        "octet string" {
            val empty = byteArrayOf()
            DER.decodeFromByteArray<ByteArray>(
                DER.encodeToByteArray(empty)
                    .also { it.toHexString() shouldBe "0400" }
            ) shouldBe empty
            val threeBytes = byteArrayOf(1, 2, 3)
            DER.decodeFromByteArray<ByteArray>(
                DER.encodeToByteArray(threeBytes)
                    .also { it.toHexString() shouldBe "0403010203" }
            ) shouldBe threeBytes
        }
    }
}

@JvmInline
@Serializable
value class BitSetValue(
    @Asn1BitString
    val bytes: ByteArray
)

@JvmInline
@Serializable
@Asn1Tag(tagNumber = 1336u)
value class BitSetValueTagged(
    @Asn1BitString
    val bytes: ByteArray
)
