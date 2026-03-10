package at.asitplus.awesn1.serialization

import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.decodeFromByteArray

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestImplicitTagging by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "Implicit tagging" - {
        val imlNothing = DER.encodeToByteArray(NothingOnClass("foo"))
        val imlClass = DER.encodeToByteArray(ImplicitOnClass("foo"))
        val imlProp = DER.encodeToByteArray(ImplicitOnProperty("foo"))
        val imlBoth = DER.encodeToByteArray(ImplicitOnBoth("foo"))

        DER.decodeFromByteArray<NothingOnClass>(imlNothing) shouldBe NothingOnClass("foo")
        DER.decodeFromByteArray<ImplicitOnClass>(imlClass) shouldBe ImplicitOnClass("foo")
        DER.decodeFromByteArray<ImplicitOnProperty>(imlProp) shouldBe ImplicitOnProperty("foo")
        DER.decodeFromByteArray<ImplicitOnBoth>(imlBoth) shouldBe ImplicitOnBoth("foo")

        shouldThrow<SerializationException> { DER.decodeFromByteArray<ImplicitOnProperty>(imlClass) }
        shouldThrow<SerializationException> { DER.decodeFromByteArray<ImplicitOnProperty>(imlBoth) }
        shouldThrow<SerializationException> { DER.decodeFromByteArray<ImplicitOnProperty>(imlNothing) }

        shouldThrow<SerializationException> { DER.decodeFromByteArray<ImplicitOnClass>(imlNothing) }
        shouldThrow<SerializationException> { DER.decodeFromByteArray<ImplicitOnClass>(imlBoth) }
        shouldThrow<SerializationException> { DER.decodeFromByteArray<ImplicitOnClass>(imlProp) }

        shouldThrow<SerializationException> { DER.decodeFromByteArray<ImplicitOnBoth>(imlProp) }
        shouldThrow<SerializationException> { DER.decodeFromByteArray<ImplicitOnBoth>(imlClass) }
        shouldThrow<SerializationException> { DER.decodeFromByteArray<ImplicitOnBoth>(imlNothing) }

        shouldThrow<SerializationException> { DER.decodeFromByteArray<NothingOnClass>(imlClass) }
        shouldThrow<SerializationException> { DER.decodeFromByteArray<NothingOnClass>(imlProp) }
        shouldThrow<SerializationException> { DER.decodeFromByteArray<NothingOnClass>(imlBoth) }

        shouldThrow<SerializationException> { DER.decodeFromByteArray<ImplicitOnClassWrong>(imlClass) }
        shouldThrow<SerializationException> { DER.decodeFromByteArray<ImplicitOnPropertyWrong>(imlProp) }
        shouldThrow<SerializationException> { DER.decodeFromByteArray<ImplicitOnBothWrong>(imlBoth) }
        shouldThrow<SerializationException> { DER.decodeFromByteArray<ImplicitOnBothWrongClass>(imlBoth) }
        shouldThrow<SerializationException> { DER.decodeFromByteArray<ImplicitOnBothWrongProperty>(imlBoth) }

        "Nested" {
            val nothingOnClassNested = DER.encodeToByteArray(

                NothingOnClassNested(NothingOnClass("foo"))
            )
            val nothingOnClassNestedOnClass = DER.encodeToByteArray(

                NothingOnClassNestedOnClass(ImplicitOnClass("foo"))
            )
            val nothingOnClassNestedOnProperty = DER.encodeToByteArray(

                NothingOnClassNestedOnProperty(NothingOnClass("foo"))
            )
            val nothingOnClassNestedOnPropertyOverride =
                DER.encodeToByteArray(

                    NothingOnClassNestedOnPropertyOverride(ImplicitOnClass("foo"))
                )

            nothingOnClassNested.toHexString() shouldBe "300730050c03666f6f"
            nothingOnClassNestedOnClass.toHexString() shouldBe "3009bf8a39050c03666f6f"
            nothingOnClassNestedOnProperty.toHexString() shouldBe "3009bf8a39050c03666f6f"
            nothingOnClassNestedOnPropertyOverride.toHexString() shouldBe "3009bf851a050c03666f6f"

            DER.decodeFromByteArray<NothingOnClassNested>(nothingOnClassNested)
            DER.decodeFromByteArray<NothingOnClassNestedOnClass>(nothingOnClassNestedOnClass)
            DER.decodeFromByteArray<NothingOnClassNestedOnClass>(nothingOnClassNestedOnProperty)
            DER.decodeFromByteArray<NothingOnClassNestedOnProperty>(nothingOnClassNestedOnProperty)
            DER.decodeFromByteArray<NothingOnClassNestedOnProperty>(nothingOnClassNestedOnClass)

            DER.decodeFromByteArray<NothingOnClassNestedOnPropertyOverride>(nothingOnClassNestedOnPropertyOverride)

            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<NothingOnClassNested>(
                    nothingOnClassNestedOnClass
                )
            }
            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<NothingOnClassNested>(nothingOnClassNestedOnProperty)
            }
            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<NothingOnClassNested>(nothingOnClassNestedOnPropertyOverride)
            }

            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<NothingOnClassNestedOnClass>(
                    nothingOnClassNested
                )
            }
            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<NothingOnClassNestedOnClass>(nothingOnClassNestedOnPropertyOverride)
            }

            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<NothingOnClassNestedOnProperty>(nothingOnClassNested)
            }
            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<NothingOnClassNestedOnProperty>(nothingOnClassNestedOnPropertyOverride)
            }

            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<NothingOnClassNestedOnPropertyOverride>(nothingOnClassNested)
            }
            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<NothingOnClassNestedOnPropertyOverride>(nothingOnClassNestedOnProperty)
            }
            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<NothingOnClassNestedOnPropertyOverride>(nothingOnClassNestedOnClass)
            }

            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<NothingOnClassNestedOnClassWrong>(nothingOnClassNested)
            }
            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<NothingOnClassNestedOnClassWrong>(nothingOnClassNestedOnClass)
            }
            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<NothingOnClassNestedOnClassWrong>(nothingOnClassNestedOnProperty)
            }
            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<NothingOnClassNestedOnClassWrong>(nothingOnClassNestedOnPropertyOverride)
            }

            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<NothingOnClassNestedOnPropertyWrong>(nothingOnClassNested)
            }
            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<NothingOnClassNestedOnPropertyWrong>(nothingOnClassNestedOnClass)
            }
            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<NothingOnClassNestedOnPropertyWrong>(nothingOnClassNestedOnProperty)
            }
            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<NothingOnClassNestedOnPropertyWrong>(nothingOnClassNestedOnPropertyOverride)
            }

            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<NothingOnClassNestedOnPropertyOverrideWrong>(nothingOnClassNested)
            }
            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<NothingOnClassNestedOnPropertyOverrideWrong>(nothingOnClassNestedOnClass)
            }
            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<NothingOnClassNestedOnPropertyOverrideWrong>(nothingOnClassNestedOnProperty)
            }
            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<NothingOnClassNestedOnPropertyOverrideWrong>(
                    nothingOnClassNestedOnPropertyOverride
                )
            }
        }
    }
}

@Serializable
data class NothingOnClass(val a: String)

@Serializable
@Asn1Tag(tagNumber = 1337u, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
data class ImplicitOnClass(val a: String)

@Serializable
@Asn1Tag(tagNumber = 7331u, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
data class ImplicitOnClassWrong(val a: String)

@Serializable
data class ImplicitOnProperty(@Asn1Tag(tagNumber = 1338u, tagClass = Asn1TagClass.CONTEXT_SPECIFIC) val a: String)

@Serializable
data class ImplicitOnPropertyWrong(@Asn1Tag(tagNumber = 8331u, tagClass = Asn1TagClass.CONTEXT_SPECIFIC) val a: String)

@Serializable
@Asn1Tag(tagNumber = 1337u, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
data class ImplicitOnBoth(@Asn1Tag(tagNumber = 1338u, tagClass = Asn1TagClass.CONTEXT_SPECIFIC) val a: String)

@Serializable
@Asn1Tag(tagNumber = 73331u, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
data class ImplicitOnBothWrong(@Asn1Tag(tagNumber = 8331u, tagClass = Asn1TagClass.CONTEXT_SPECIFIC) val a: String)

@Serializable
@Asn1Tag(tagNumber = 7331u, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
data class ImplicitOnBothWrongClass(@Asn1Tag(tagNumber = 1338u, tagClass = Asn1TagClass.CONTEXT_SPECIFIC) val a: String)

@Serializable
@Asn1Tag(tagNumber = 1337u, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
data class ImplicitOnBothWrongProperty(
    @Asn1Tag(
        tagNumber = 8331u,
        tagClass = Asn1TagClass.CONTEXT_SPECIFIC
    ) val a: String
)

@Serializable
data class NothingOnClassNested(val a: NothingOnClass)

@Serializable
data class NothingOnClassNestedOnClass(val a: ImplicitOnClass)

@Serializable
data class NothingOnClassNestedOnClassWrong(val a: ImplicitOnClassWrong)

@Serializable
data class NothingOnClassNestedOnProperty(
    @Asn1Tag(
        tagNumber = 1337u,
        tagClass = Asn1TagClass.CONTEXT_SPECIFIC
    ) val a: NothingOnClass
)

@Serializable
data class NothingOnClassNestedOnPropertyWrong(
    @Asn1Tag(
        tagNumber = 333u,
        tagClass = Asn1TagClass.CONTEXT_SPECIFIC
    ) val a: NothingOnClass
)

@Serializable
data class NothingOnClassNestedOnPropertyOverride(
    @Asn1Tag(
        tagNumber = 666u,
        tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
    ) val a: ImplicitOnClass
)

@Serializable
data class NothingOnClassNestedOnPropertyOverrideWrong(
    @Asn1Tag(
        tagNumber = 999u,
        tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
    ) val a: ImplicitOnClass
)
