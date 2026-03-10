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
val SerializationTutorial01Baseline by testSuite(
    testConfig = DefaultConfiguration
) {
    "Baseline mapping without ASN.1 annotations" {
        val value = TutorialPerson(name = "A", age = 5)
        val der = Buffer().apply { DER.encodeToSink( value, this) }.readByteArray()
        der.toHexString() shouldBe "30060c0141020105"
        DER.decodeFromSource<TutorialPerson>(Buffer().apply { write(der) }) shouldBe value
    }
}

@Serializable
private data class TutorialPerson(
    val name: String,
    val age: Int,
)
