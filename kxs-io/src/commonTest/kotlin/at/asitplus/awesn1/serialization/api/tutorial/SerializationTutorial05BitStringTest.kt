package at.asitplus.awesn1.serialization.api
import at.asitplus.awesn1.io.decodeFromSource
import at.asitplus.awesn1.io.encodeToSink
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import at.asitplus.awesn1.serialization.*


import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

@OptIn(ExperimentalStdlibApi::class)
val SerializationTutorial05BitString by testSuite(
    testConfig = DefaultConfiguration
) {
    "BIT STRING mapping with @Asn1BitString on ByteArray" {
        val value = TutorialBitStringCarrier(byteArrayOf(0xAA.toByte()))
        val der = Buffer().apply { DER.encodeToSink(value, this) }.readByteArray()
        der.toHexString() shouldBe "3004030200aa"
        val decoded = DER.decodeFromSource<TutorialBitStringCarrier>(Buffer().apply { write(der) })
        decoded shouldNotBe value
        decoded.bits.contentToString() shouldBe value.bits.contentToString()
    }
}

@Serializable
private data class TutorialBitStringCarrier(
    @Asn1BitString
    val bits: ByteArray,
)
