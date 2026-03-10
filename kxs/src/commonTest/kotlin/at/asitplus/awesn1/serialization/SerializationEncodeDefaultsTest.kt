package at.asitplus.awesn1.serialization

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestEncodeDefaults by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "Default DER instance encodes default-valued properties" {
        val value = EncodeDefaultsSimple()
        val encoded =
            DER.encodeToByteArray(value)
        encoded.toHexString() shouldBe "30060201010c0178"
        DER.decodeFromByteArray<EncodeDefaultsSimple>(encoded) shouldBe value
    }

    "encodeDefaults=false omits default-valued properties" {
        val derNoDefaults = DER { encodeDefaults = false }

        val value = EncodeDefaultsSimple()
        val encoded = derNoDefaults.encodeToByteArray(value)
        encoded.toHexString() shouldBe "3000"
        derNoDefaults.decodeFromByteArray<EncodeDefaultsSimple>(encoded) shouldBe value
    }

    "encodeDefaults=false still encodes non-default values" {
        val derNoDefaults = DER { encodeDefaults = false }

        val value = EncodeDefaultsSimple(number = 2, text = "y")
        val encoded = derNoDefaults.encodeToByteArray(value)
        encoded.toHexString() shouldBe "30060201020c0179"
        derNoDefaults.decodeFromByteArray<EncodeDefaultsSimple>(encoded) shouldBe value
    }

    "encodeDefaults=false omits only defaulted fields in mixed classes" {
        val derNoDefaults = DER { encodeDefaults = false }

        val defaultsOnly = EncodeDefaultsMixed(required = 5)
        val defaultsOnlyEncoded = derNoDefaults.encodeToByteArray(defaultsOnly)
        defaultsOnlyEncoded.toHexString() shouldBe "3003020105"
        derNoDefaults.decodeFromByteArray<EncodeDefaultsMixed>(defaultsOnlyEncoded) shouldBe defaultsOnly

        val withOverrides = EncodeDefaultsMixed(required = 5, optionalInt = 8, optionalText = "a")
        val withOverridesEncoded = derNoDefaults.encodeToByteArray(withOverrides)
        withOverridesEncoded.toHexString() shouldBe "30090201050201080c0161"
        derNoDefaults.decodeFromByteArray<EncodeDefaultsMixed>(withOverridesEncoded) shouldBe withOverrides
    }
}

@Serializable
data class EncodeDefaultsSimple(
    val number: Int = 1,
    val text: String = "x",
)

@Serializable
data class EncodeDefaultsMixed(
    val required: Int,
    val optionalInt: Int = 7,
    val optionalText: String = "ok",
)
