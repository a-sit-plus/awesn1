package at.asitplus.awesn1.serialization.api
import at.asitplus.awesn1.io.decodeFromSource
import at.asitplus.awesn1.io.encodeToSink
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import at.asitplus.awesn1.serialization.*


import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

@OptIn(ExperimentalStdlibApi::class)
val SerializationTutorial06Choice by testSuite(
    testConfig = DefaultConfiguration
) {
    "Sealed CHOICE uses sealed polymorphism" - {
        "INT" {
            val value = (TutorialChoiceInt(7))
            val der = Buffer().apply { DER.encodeToSink(value, this) }.readByteArray()
            der.toHexString() shouldBe "3003020107"
            DER.decodeFromSource<TutorialChoice>(Buffer().apply { write(der) }) shouldBe value
        }
        "BOOL" {
            val value = (TutorialChoiceBool(true))
            val der = Buffer().apply { DER.encodeToSink(value, this) }.readByteArray()
            der.toHexString() shouldBe "bf8a39030101ff"
            DER.decodeFromSource<TutorialChoice>(Buffer().apply { write(der) }) shouldBe value
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
