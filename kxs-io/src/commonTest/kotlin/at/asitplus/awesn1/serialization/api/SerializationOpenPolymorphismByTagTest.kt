package at.asitplus.awesn1.serialization.api
import at.asitplus.awesn1.io.decodeFromSource
import at.asitplus.awesn1.io.encodeToSink
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import at.asitplus.awesn1.serialization.*


import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.modules.SerializersModule
import kotlin.jvm.JvmInline

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestOpenPolymorphismByTag by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "Open-polymorphic tag dispatch round-trips with registered subtypes" {
        val der = derWithOpenByTag(includeBool = false)
        val intValue: OpenByTag = OpenByTagInt(7)
        val strValue: OpenByTag = OpenByTagString("hello")

        der.decodeFromSource<OpenByTag>(Buffer().apply { write(
            Buffer().apply { der.encodeToSink(intValue, this) }.readByteArray()
        ) }) shouldBe intValue
        der.decodeFromSource<OpenByTag>(Buffer().apply { write(
            Buffer().apply { der.encodeToSink(strValue, this) }.readByteArray()
        ) }) shouldBe strValue
    }

    "Additional subtype can be enabled by extending the DER serializers module" {
        val strictDer = derWithOpenByTag(includeBool = false)
        val extendedDer = derWithOpenByTag(includeBool = true)
        val boolValue: OpenByTag = OpenByTagBool(true)

        shouldThrow<SerializationException> {
            Buffer().apply { strictDer.encodeToSink(boolValue, this) }.readByteArray()
        }.message.shouldContain("No registered open-polymorphic subtype")

        val encoded = Buffer().apply { extendedDer.encodeToSink(boolValue, this) }.readByteArray()
        extendedDer.decodeFromSource<OpenByTag>(Buffer().apply { write(encoded) }) shouldBe boolValue

        shouldThrow<SerializationException> {
            strictDer.decodeFromSource<OpenByTag>(Buffer().apply { write(encoded) })
        }.message.shouldContain("No registered open-polymorphic subtype")
    }
}

interface OpenByTag

@Serializable
@JvmInline
value class OpenByTagInt(val value: Int) : OpenByTag

@Serializable
@Asn1Tag(tagNumber = 1u, tagClass = Asn1TagClass.CONTEXT_SPECIFIC, constructed = Asn1ConstructedBit.PRIMITIVE)
@JvmInline
value class OpenByTagString(val value: String) : OpenByTag

@Serializable
@Asn1Tag(tagNumber = 2u, tagClass = Asn1TagClass.CONTEXT_SPECIFIC, constructed = Asn1ConstructedBit.PRIMITIVE)
@JvmInline
value class OpenByTagBool(val value: Boolean) : OpenByTag

private fun derWithOpenByTag(includeBool: Boolean) = DER {
    serializersModule = SerializersModule {
        polymorphicByTag(OpenByTag::class, serialName = "OpenByTag") {
            subtype<OpenByTagInt>()
            subtype<OpenByTagString>()
            if (includeBool) {
                subtype<OpenByTagBool>()
            }
        }
    }
}
