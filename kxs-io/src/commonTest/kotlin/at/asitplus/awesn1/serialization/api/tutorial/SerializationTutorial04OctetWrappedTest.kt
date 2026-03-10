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
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.serializer

@OptIn(ExperimentalStdlibApi::class)
val SerializationTutorial04OctetWrapped by testSuite(
    testConfig = DefaultConfiguration
) {
    "OCTET STRING encapsulation with Asn1OctetWrapped" {
        val value = TutorialOctetCarrier(
            wrapped = OctetStringEncapsulated(5),
        )
        val der =            Buffer().apply { DER.encodeToSink( value, this) }.readByteArray()
        der.toHexString() shouldBe "30050403020105"
        DER.decodeFromSource<TutorialOctetCarrier>(Buffer().apply { write(der) }) shouldBe value
    }
}

@Serializable
private data class TutorialOctetCarrier(
    val wrapped: OctetStringEncapsulated<Int>,
)
