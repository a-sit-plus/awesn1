package at.asitplus.awesn1.serialization

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

@OptIn(ExperimentalStdlibApi::class)
val SerializationTutorial12MapAndSet by testSuite(
    testConfig = DefaultConfiguration
) {
    "Map and Set default mappings" {
        val value = TutorialMapAndSet(
            map = mapOf(1 to 2),
            set = setOf(3),
        )
        val der = DER.encodeToByteArray(value)
        der.toHexString() shouldBe "300d30060201010201023103020103"
        DER.decodeFromByteArray<TutorialMapAndSet>(der) shouldBe value
    }
}

@Serializable
private data class TutorialMapAndSet(
    val map: Map<Int, Int>,
    val set: Set<Int>,
)
