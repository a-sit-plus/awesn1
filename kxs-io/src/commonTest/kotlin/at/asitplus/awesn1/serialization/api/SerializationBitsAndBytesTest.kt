package at.asitplus.awesn1.serialization.api
import at.asitplus.awesn1.io.decodeFromSource
import at.asitplus.awesn1.io.encodeToSink
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import at.asitplus.awesn1.serialization.*


import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlin.jvm.JvmInline

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestBitsAndBytes by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "Bits and Bytes" - {
        "Bit string" {
            val empty = byteArrayOf()
            val valueClassEmpty = BitSetValue(empty)
            val valueClass = BitSetValue(byteArrayOf(1, 2, 3))

            DER.decodeFromSource<BitSetValue>(Buffer().apply { write(
                Buffer().apply { DER.encodeToSink(valueClassEmpty, this) }.readByteArray().also { it.toHexString() shouldBe "030100" }
            ) }).bytes shouldBe valueClassEmpty.bytes

            DER.decodeFromSource<BitSetValue>(Buffer().apply { write(
                Buffer().apply { DER.encodeToSink(valueClass, this) }.readByteArray()
                    .also { it.toHexString() shouldBe "030400010203" }
            ) }).bytes shouldBe valueClass.bytes

            val tagged = BitSetValueTagged(byteArrayOf(0x01, 0x02))
            DER.decodeFromSource<BitSetValueTagged>(Buffer().apply { write(
                Buffer().apply { DER.encodeToSink(tagged, this) }.readByteArray()
            ) }).bytes.toList() shouldBe tagged.bytes.toList()
        }

        "octet string" {
            val empty = byteArrayOf()
            DER.decodeFromSource<ByteArray>(Buffer().apply { write(
                Buffer().apply { DER.encodeToSink(empty, this) }.readByteArray()
                    .also { it.toHexString() shouldBe "0400" }
            ) }) shouldBe empty
            val threeBytes = byteArrayOf(1, 2, 3)
            DER.decodeFromSource<ByteArray>(Buffer().apply { write(
                Buffer().apply { DER.encodeToSink(threeBytes, this) }.readByteArray()
                    .also { it.toHexString() shouldBe "0403010203" }
            ) }) shouldBe threeBytes
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
