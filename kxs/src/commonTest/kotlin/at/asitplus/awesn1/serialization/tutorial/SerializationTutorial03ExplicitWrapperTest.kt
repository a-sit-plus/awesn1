package at.asitplus.awesn1.serialization

import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

@OptIn(ExperimentalStdlibApi::class)
val SerializationTutorial03ExplicitWrapper by matrixSuite(
    testConfig = DefaultConfiguration
) {
    "EXPLICIT modeling with Asn1Explicit + context-specific constructed tag" {
        val value = TutorialExplicitCarrier(
            wrapped = ExplicitlyTagged(5),
        )
        val der = DER.encodeToByteArray(value)
        der.toHexString() shouldBe "3005a003020105"
        DER.decodeFromByteArray<TutorialExplicitCarrier>(der) shouldBe value
    }
}

@Serializable
private data class TutorialExplicitCarrier(
    @Asn1Tag(
        tagNumber = 0u,
        tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC,
        constructed = Asn1Tag.ConstructedBit.CONSTRUCTED,
    )
    val wrapped: ExplicitlyTagged<Int>,
)
