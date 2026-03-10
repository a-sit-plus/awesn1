package at.asitplus.awesn1.serialization.api
import at.asitplus.awesn1.io.decodeFromSource
import at.asitplus.awesn1.io.encodeToSink
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import at.asitplus.awesn1.serialization.*


import at.asitplus.awesn1.Asn1Null
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
val SerializationTestNullAndSet by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "SET semantics" {
        val set = setOf("Foo", "Bar", "Baz")
        DER.decodeFromSource<Set<String>>(Buffer().apply { write(
            Buffer().apply { DER.encodeToSink(set, this) }.readByteArray()
                .also { it.toHexString() shouldBe "310f0c034261720c0342617a0c03466f6f" }
        ) }) shouldBe set
    }

    "Nulls and Noughts" {
        val derExplicitNulls = DER { explicitNulls = true }
        Buffer().apply { DER.encodeToSink(

            null
        , this) }.readByteArray() shouldBe byteArrayOf()
        Buffer().apply { derExplicitNulls.encodeToSink(

            null
        , this) }.readByteArray() shouldBe Asn1Null.derEncoded

        val nullable: String? = null
        Buffer().apply { DER.encodeToSink(nullable, this) }.readByteArray() shouldBe byteArrayOf()
        DER.decodeFromSource<String?>(Buffer().apply { write(byteArrayOf()) }) shouldBe null

        val taggedNull = TaggedNullableInt(value = null)
        derExplicitNulls.decodeFromSource<TaggedNullableInt>(Buffer().apply { write(Buffer().apply { derExplicitNulls.encodeToSink(taggedNull, this) }.readByteArray()) }) shouldBe taggedNull

        val taggedValue = TaggedNullableInt(value = 5)
        derExplicitNulls.decodeFromSource<TaggedNullableInt>(Buffer().apply { write(
            Buffer().apply { derExplicitNulls.encodeToSink(taggedValue, this) }.readByteArray()
        ) }) shouldBe taggedValue

        val omitted = TaggedNullableIntOmit(value = null)
        DER.decodeFromSource<TaggedNullableIntOmit>(Buffer().apply { write(
            Buffer().apply { DER.encodeToSink(omitted, this) }.readByteArray()
        ) }) shouldBe omitted

        // Regression: empty primitive values must not be mistaken for null when explicitNulls=false.
        val emptyString = NullablePlainString("")
        DER.decodeFromSource<NullablePlainString>(Buffer().apply { write(
            Buffer().apply { DER.encodeToSink(emptyString, this) }.readByteArray()
        ) }) shouldBe emptyString

        val nullString = NullablePlainString(null)
        DER.decodeFromSource<NullablePlainString>(Buffer().apply { write(
            Buffer().apply { DER.encodeToSink(nullString, this) }.readByteArray()
        ) }) shouldBe nullString
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
