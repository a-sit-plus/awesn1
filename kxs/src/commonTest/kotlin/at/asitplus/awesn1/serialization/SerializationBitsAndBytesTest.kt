package at.asitplus.awesn1.serialization

import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.decodeFromHexString
import kotlinx.serialization.encodeToByteArray
import kotlin.jvm.JvmInline
import at.asitplus.awesn1.Asn1BitString as Asn1BitStringValue

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestBitsAndBytes by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
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
            }.message shouldBe "Byte Arrays deserialized from BIT STRING must not have padding bits. Found 1 padding bits. If you require padding, directly use Asn1BitString to represent the property."

            shouldThrow<SerializationException> {
                DER.decodeFromHexString<Asn1BitStringValue>("03020105")
            }.message shouldBe "Last 1 padding bits must be zeroed out. Last byte is: 00000101"

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
