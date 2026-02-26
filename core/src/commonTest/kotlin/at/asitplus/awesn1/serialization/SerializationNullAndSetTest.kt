package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.Asn1Null
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestNullAndSet by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "SET semantics" {
        val set = setOf("Foo", "Bar", "Baz")
        DER.decodeFromByteArray<Set<String>>(
            DER.encodeToByteArray(set).also { it.toHexString() shouldBe "310f0c03466f6f0c034261720c0342617a" }
        ) shouldBe set
    }

    "Nulls and Noughts" {
        val derExplicitNulls = DER { explicitNulls = true }
        DER.encodeToByteArray<NullAsAsn1Null?>(null) shouldBe byteArrayOf()
        derExplicitNulls.encodeToByteArray<NullAsAsn1Null?>(null) shouldBe Asn1Null.derEncoded

        val nullable: String? = null
        DER.encodeToByteArray(nullable) shouldBe byteArrayOf()
        DER.decodeFromByteArray<String?>(byteArrayOf()) shouldBe null

        val taggedNull = TaggedNullableInt(value = null)
        derExplicitNulls.decodeFromByteArray<TaggedNullableInt>(derExplicitNulls.encodeToByteArray(taggedNull)) shouldBe taggedNull

        val taggedValue = TaggedNullableInt(value = 5)
        derExplicitNulls.decodeFromByteArray<TaggedNullableInt>(derExplicitNulls.encodeToByteArray(taggedValue)) shouldBe taggedValue

        val omitted = TaggedNullableIntOmit(value = null)
        DER.decodeFromByteArray<TaggedNullableIntOmit>(DER.encodeToByteArray(omitted)) shouldBe omitted

        // Regression: empty primitive values must not be mistaken for null when explicitNulls=false.
        val emptyString = NullablePlainString("")
        DER.decodeFromByteArray<NullablePlainString>(DER.encodeToByteArray(emptyString)) shouldBe emptyString

        val nullString = NullablePlainString(null)
        DER.decodeFromByteArray<NullablePlainString>(DER.encodeToByteArray(nullString)) shouldBe nullString
    }
}

@Serializable
object NullAsAsn1Null

@Serializable
data class TaggedNullableInt(
    @Asn1Tag(
        tagNumber = 90u,
        tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
    )
    val value: Int?
)

@Serializable
data class TaggedNullableIntOmit(
    @Asn1Tag(
        tagNumber = 90u,
        tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
    )
    val value: Int?
)

@Serializable
data class NullablePlainString(
    val value: String?
)
