package at.asitplus.awesn1.serialization

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.modules.SerializersModule

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestPolymorphismAndChoice by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "Number of elements" {
        val withThreeOtherNull = WithThreeNullable("first", null, "3")

        DER.encodeToByteArray(withThreeOtherNull).apply {
            toHexString() shouldBe "bf8a3d0a0c0566697273740c0133"
            DER.decodeFromByteArray<WithThreeNullable>(this) shouldBe withThreeOtherNull
        }

        val withThreeOther = WithThreeNullable("first", 2, "3")

        DER.encodeToByteArray(withThreeOther).apply {
            toHexString() shouldBe "bf8a3d0d0c0566697273740201020c0133"
            DER.decodeFromByteArray<WithThreeNullable>(this) shouldBe withThreeOther
        }

        val without = Without
        val withOne = WithOne("")
        val withTwo = WithTwo("1", "2")
        val withTwoOther = WithTwoOther("1", 2)
        val withThree = WithThree("1", "3", "3")

        DER.encodeToByteArray(without).apply {
            toHexString() shouldBe "3000"
            DER.decodeFromByteArray<Without>(this) shouldBe without
        }

        shouldThrow<SerializationException> { DER.decodeFromByteArray<Without>("30020c00".hexToByteArray()) }

        DER.encodeToByteArray(withOne).apply {
            toHexString() shouldBe "bf8a39020c00"
            DER.decodeFromByteArray<WithOne>(this) shouldBe withOne
        }

        DER.encodeToByteArray(withTwo).apply {
            toHexString() shouldBe "bf8a3a060c01310c0132"
            DER.decodeFromByteArray<WithTwo>(this) shouldBe withTwo
        }

        DER.encodeToByteArray(withTwoOther).apply {
            toHexString() shouldBe "bf8a3b060c0131020102"
            DER.decodeFromByteArray<WithTwoOther>(this) shouldBe withTwoOther
        }

        DER.encodeToByteArray(withThree).apply {
            toHexString() shouldBe "bf8a3c090c01310c01330c0133"
            DER.decodeFromByteArray<WithThree>(this) shouldBe withThree
        }
    }

    "Polymorphic" {
        val without = Without
        val withOne = WithOne("")
        val withTwo = WithTwo("1", "2")
        val withTwoOther = WithTwoOther("1", 2)
        val withThree = WithThree("1", "3", "3")


        //not registered
        shouldThrow<SerializationException> {
            DER.decodeFromByteArray<List<AnInterface>>(
                "30293000bf8a39020c00bf8a3a060c01310c0132bf8a3b060c0131020102bf8a3c090c01310c01330c0133".hexToByteArray()
            )
        }
        val der = DER {
            serializersModule = SerializersModule {
                polymorphicByTag(AnInterface::class) {
                    subtype<Without>()
                    subtype<WithOne>()
                    subtype<WithTwo>()
                    subtype<WithTwoOther>()
                    subtype<WithThree>()
                }
            }
        }

        val listOf = listOf(without, withOne, withTwo, withTwoOther, withThree)
        //Registered
        der.decodeFromByteArray<List<AnInterface>>(
            "30293000bf8a39020c00bf8a3a060c01310c0132bf8a3b060c0131020102bf8a3c090c01310c01330c0133".hexToByteArray()
        ) shouldBe listOf


        //junk
        shouldThrow<SerializationException> {
            der.decodeFromByteArray<List<AnInterface>>(
                "3082017730430c3f61742e61736974706c75732e7369676e756d2e696e64697370656e7361626c652e61736e312e73657269616c697a6174696f6e2e6170692e576974686f7574300030450c3f61742e61736974706c75732e7369676e756d2e696e64697370656e7361626c652e61736e312e73657269616c697a6174696f6e2e6170692e576974684f6e6530020c0030490c3f61742e61736974706c75732e7369676e756d2e696e64697370656e7361626c652e61736e312e73657269616c697a6174696f6e2e6170692e5769746854776f30060c01310c0132304e0c4461742e61736974706c75732e7369676e756d2e696e64697370656e7361626c652e61736e312e73657269616c697a6174696f6e2e6170692e5769746854776f4f7468657230060c0131020102304e0c4161742e61736974706c75732e7369676e756d2e696e64697370656e7361626c652e61736e312e73657269616c697a6174696f6e2e6170692e57697468546872656530090c01310c01330c0133".hexToByteArray()
            )
        }

        der.decodeFromByteArray<List<AnInterface>>(
            der.encodeToByteArray(listOf)
                .also { println(it.toHexString()) }
        ) shouldBe listOf
    }

    "Choice polymorphism (sealed only)" {
        val intChoice = ChoiceContainer(ChoiceInt(7))
        val taggedStringChoice = ChoiceContainer(ChoiceTaggedString("foo"))

        DER.decodeFromByteArray<ChoiceContainer>(DER.encodeToByteArray(intChoice)) shouldBe intChoice
        DER.decodeFromByteArray<ChoiceContainer>(DER.encodeToByteArray(taggedStringChoice)) shouldBe taggedStringChoice

        val list = listOf<ChoiceInterface>(ChoiceInt(1), ChoiceTaggedString("bar"))
        DER.decodeFromByteArray<List<ChoiceInterface>>(DER.encodeToByteArray(list)) shouldBe list
    }

    "Choice ambiguity is rejected at runtime" {
        val encoded = DER.encodeToByteArray(AmbiguousChoiceA("foo"))
        shouldThrow<SerializationException> {
            DER.decodeFromByteArray<AmbiguousChoice>(encoded)
        }
    }
}

interface AnInterface

// @formatter:off
@Serializable object Without : AnInterface

@Asn1Tag(1337u)
@Serializable data class WithOne(val first: String) : AnInterface
@Asn1Tag(1338u)
@Serializable data class WithTwo(val first: String, val second: String) : AnInterface
@Asn1Tag(1339u)
@Serializable data class WithTwoOther(val first: String, val second: Int) : AnInterface
@Asn1Tag(1340u)
@Serializable data class WithThree(val first: String, val second: String, val third: String) : AnInterface
@Asn1Tag(1341u)
@Serializable data class WithThreeNullable(val first: String, val second: Int?, val third: String)
// @formatter:on

@Serializable
sealed interface ChoiceInterface

@Serializable
data class ChoiceContainer(val choice: ChoiceInterface)

@Serializable
data class ChoiceInt(val value: Int) : ChoiceInterface

@Serializable
@Asn1Tag(tagNumber = 1u)
data class ChoiceTaggedString(val value: String) : ChoiceInterface

@Serializable
sealed interface AmbiguousChoice

@Serializable
data class AmbiguousChoiceA(val value: String) : AmbiguousChoice

@Serializable
data class AmbiguousChoiceB(val value: String) : AmbiguousChoice
