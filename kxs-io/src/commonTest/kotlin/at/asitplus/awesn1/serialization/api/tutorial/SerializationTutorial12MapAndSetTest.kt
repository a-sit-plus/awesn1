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

@OptIn(ExperimentalStdlibApi::class)
val SerializationTutorial12MapAndSet by testSuite(
    testConfig = DefaultConfiguration
) {
    "Map and Set default mappings" {
        val value = TutorialMapAndSet(
            map = mapOf(1 to 2),
            set = setOf(3),
        )
        val der = Buffer().apply { DER.encodeToSink(value, this) }.readByteArray()
        der.toHexString() shouldBe "300d30060201010201023103020103"
        DER.decodeFromSource<TutorialMapAndSet>(Buffer().apply { write(der) }) shouldBe value
    }
}

@Serializable
private data class TutorialMapAndSet(
    val map: Map<Int, Int>,
    val set: Set<Int>,
)
