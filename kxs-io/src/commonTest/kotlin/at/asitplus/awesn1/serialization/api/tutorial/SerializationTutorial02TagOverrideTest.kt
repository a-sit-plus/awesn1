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
val SerializationTutorial02TagOverride by matrixSuite {
    "Implicit tag override with @Asn1Tag" {
        val value = TutorialTaggedInt(value = 5)
        val der = Buffer().apply { DER.encodeToSink(value, this) }.readByteArray()
        der.toHexString() shouldBe "3003800105"
        DER.decodeFromSource<TutorialTaggedInt>(Buffer().apply { write(der) }) shouldBe value
    }
}

@Serializable
private data class TutorialTaggedInt(
    @Asn1Tag(
        tagNumber = 0u,
        tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC,
        constructed = Asn1Tag.ConstructedBit.PRIMITIVE,
    )
    val value: Int,
)
