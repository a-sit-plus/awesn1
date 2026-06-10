package at.asitplus.awesn1.serialization.api
import at.asitplus.awesn1.io.decodeFromSource
import at.asitplus.awesn1.io.encodeToSink
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import at.asitplus.awesn1.serialization.*


import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

@OptIn(ExperimentalStdlibApi::class)
val SerializationTutorial09EncodeDefaults by matrixSuite {
    "encodeDefaults=false omits default-valued properties" {
        val format = DER { encodeDefaults = false }
        val value = TutorialDefaults()
        val der = Buffer().apply { format.encodeToSink(value, this) }.readByteArray()
        der.toHexString() shouldBe "3000"
        format.decodeFromSource<TutorialDefaults>(Buffer().apply { write(der) }) shouldBe value
    }
}

@Serializable
private data class TutorialDefaults(
    val first: Int = 1,
    val second: Boolean = true,
)
