package at.asitplus.awesn1.serialization

import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

@OptIn(ExperimentalStdlibApi::class)
val SerializationTutorial09EncodeDefaults by matrixSuite(
    testConfig = DefaultConfiguration
) {
    "encodeDefaults=false omits default-valued properties" {
        val format = DER { encodeDefaults = false }
        val value = TutorialDefaults()
        val der = format.encodeToByteArray(value)
        der.toHexString() shouldBe "3000"
        format.decodeFromByteArray<TutorialDefaults>(der) shouldBe value
    }
}

@Serializable
private data class TutorialDefaults(
    val first: Int = 1,
    val second: Boolean = true,
)
