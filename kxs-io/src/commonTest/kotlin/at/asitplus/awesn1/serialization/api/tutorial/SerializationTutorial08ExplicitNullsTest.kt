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
val SerializationTutorial08ExplicitNulls by testSuite(
    testConfig = DefaultConfiguration
) {
    "explicitNulls=true encodes null as ASN.1 NULL" {
        val format = DER { explicitNulls = true }
        val value = TutorialNullableInt(value = null)
        val der = Buffer().apply { format.encodeToSink(value, this) }.readByteArray()
        der.toHexString() shouldBe "30020500"
        format.decodeFromSource<TutorialNullableInt>(Buffer().apply { write(der) }) shouldBe value
    }
}

@Serializable
private data class TutorialNullableInt(
    val value: Int?,
)
