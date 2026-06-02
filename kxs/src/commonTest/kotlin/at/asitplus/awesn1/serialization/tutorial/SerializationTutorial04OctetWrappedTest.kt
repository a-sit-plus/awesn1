package at.asitplus.awesn1.serialization

import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

@OptIn(ExperimentalStdlibApi::class)
val SerializationTutorial04OctetWrapped by matrixSuite(
    testConfig = DefaultConfiguration
) {
    "OCTET STRING encapsulation with Asn1OctetWrapped" {
        val value = TutorialOctetCarrier(
            wrapped = OctetStringEncapsulated(5),
        )
        val der = DER.encodeToByteArray(value)
        der.toHexString() shouldBe "30050403020105"
        DER.decodeFromByteArray<TutorialOctetCarrier>(der) shouldBe value
    }
}

@Serializable
private data class TutorialOctetCarrier(
    val wrapped: OctetStringEncapsulated<Int>,
)
