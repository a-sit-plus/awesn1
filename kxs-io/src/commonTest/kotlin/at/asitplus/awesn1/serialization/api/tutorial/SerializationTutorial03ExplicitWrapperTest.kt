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
val SerializationTutorial03ExplicitWrapper by testSuite(
    testConfig = DefaultConfiguration
) {
    "EXPLICIT modeling with Asn1Explicit + context-specific constructed tag" {
        val value = TutorialExplicitCarrier(
            wrapped = ExplicitlyTagged(5),
        )
        val der = Buffer().apply { DER.encodeToSink(value, this) }.readByteArray()
        der.toHexString() shouldBe "3005a003020105"
        DER.decodeFromSource<TutorialExplicitCarrier>(Buffer().apply { write(der) }) shouldBe value
    }
}

@Serializable
private data class TutorialExplicitCarrier(
    @Asn1Tag(
        tagNumber = 0u,
        tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
        constructed = Asn1ConstructedBit.CONSTRUCTED,
    )
    val wrapped: ExplicitlyTagged<Int>,
)
