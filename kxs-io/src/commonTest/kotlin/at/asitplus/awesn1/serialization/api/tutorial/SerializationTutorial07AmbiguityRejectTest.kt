package at.asitplus.awesn1.serialization.api
import at.asitplus.awesn1.io.decodeFromSource
import at.asitplus.awesn1.io.encodeToSink
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import at.asitplus.awesn1.serialization.*


import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.string.shouldContain
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.encodeToByteArray

val SerializationTutorial07AmbiguityReject by testSuite(
    testConfig = DefaultConfiguration
) {
    "Ambiguous nullable layout is rejected" {
        shouldThrow<SerializationException> {
            Buffer().apply { DER.encodeToSink(TutorialAmbiguous(first = null, second = 9), this) }.readByteArray()
        }.message.shouldContain("Ambiguous ASN.1 layout")
    }
}

@Serializable
private data class TutorialAmbiguous(
    val first: Int?,
    val second: Int?,
)
