package at.asitplus.awesn1.serialization.api
import at.asitplus.awesn1.io.decodeFromSource
import at.asitplus.awesn1.io.encodeToSink
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import at.asitplus.awesn1.serialization.*


import at.asitplus.awesn1.Identifiable
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.modules.SerializersModule
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid


val SerializationTutorial11OpenPolyByOid by testSuite(
    testConfig = DefaultConfiguration
) {
    "Open polymorphism by OID" {
        val derCodec = DER {
            serializersModule = SerializersModule {
                polymorphicByOid(TutorialOpenByOid::class, serialName = "TutorialOpenByOid") {
                    subtype<TutorialOpenByOidInt>(TutorialOpenByOidInt)
                    subtype<TutorialOpenByOidOtherInt>(TutorialOpenByOidOtherInt)
                }
            }
        }

        val value: TutorialOpenByOid = TutorialOpenByOidInt(value = 9)
        val der = Buffer().apply { derCodec.encodeToSink(value, this) }.readByteArray()
        der.toHexString() shouldBe "30190614698192b2e2c8dbfcf294f58cc9b5f2ac87948247020109"
        derCodec.decodeFromSource<TutorialOpenByOid>(Buffer().apply { write("30190614698192b2e2c8dbfcf294f58cc9b5f2ac87948247020109".hexToByteArray()) }) shouldBe value
    }
}

private interface TutorialOpenByOid : Identifiable

@Serializable
private data class TutorialOpenByOidInt(
    val value: Int,
) : TutorialOpenByOid, Identifiable by Companion {
    companion object : OidProvider<TutorialOpenByOidInt> {
        @OptIn(ExperimentalUuidApi::class)
        override val oid: ObjectIdentifier = ObjectIdentifier(Uuid.parse("4932c522-dfce-453a-8c92-d792c0e50147"))

    }
}

@Serializable
private data class TutorialOpenByOidOtherInt(
    val value: Int,
) : TutorialOpenByOid, Identifiable by Companion {
    companion object : OidProvider<TutorialOpenByOidOtherInt> {
        @OptIn(ExperimentalUuidApi::class)
        override val oid: ObjectIdentifier = ObjectIdentifier(Uuid.parse("c29b4beb-1446-446a-b017-f5bda01d9a26"))

    }
}
