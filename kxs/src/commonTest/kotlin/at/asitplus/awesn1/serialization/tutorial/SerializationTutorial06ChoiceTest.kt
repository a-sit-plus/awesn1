package at.asitplus.awesn1.serialization

import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

@OptIn(ExperimentalStdlibApi::class)
val SerializationTutorial06Choice by matrixSuite(
    testConfig = DefaultConfiguration
) {
    "Sealed CHOICE uses sealed polymorphism" - {
        "INT" {
            val value = (TutorialChoiceInt(7))
            val der = DER.encodeToByteArray(value)
            der.toHexString() shouldBe "3003020107"
            DER.decodeFromByteArray<TutorialChoice>(der) shouldBe value
        }
        "BOOL" {
            val value = (TutorialChoiceBool(true))
            val der = DER.encodeToByteArray(value)
            der.toHexString() shouldBe "bf8a39030101ff"
            DER.decodeFromByteArray<TutorialChoice>(der) shouldBe value
        }
    }
}

@Serializable
private sealed interface TutorialChoice

@Serializable
private data class TutorialChoiceInt(
    val value: Int,
) : TutorialChoice

@Serializable
@Asn1Tag(1337u)
private data class TutorialChoiceBool(
    val value: Boolean,
) : TutorialChoice
