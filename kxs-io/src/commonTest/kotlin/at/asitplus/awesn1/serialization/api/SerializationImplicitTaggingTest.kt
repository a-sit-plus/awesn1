package at.asitplus.awesn1.serialization.api
import at.asitplus.awesn1.io.decodeFromSource
import at.asitplus.awesn1.io.encodeToSink
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import at.asitplus.awesn1.serialization.*


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
        val imlNothing = Buffer().apply { DER.encodeToSink(NothingOnClass("foo"), this) }.readByteArray()
        val imlClass = Buffer().apply { DER.encodeToSink(ImplicitOnClass("foo"), this) }.readByteArray()
        val imlProp = Buffer().apply { DER.encodeToSink(ImplicitOnProperty("foo"), this) }.readByteArray()
        val imlBoth = Buffer().apply { DER.encodeToSink(ImplicitOnBoth("foo"), this) }.readByteArray()

        DER.decodeFromSource<NothingOnClass>(Buffer().apply { write(imlNothing) }) shouldBe NothingOnClass("foo")
        DER.decodeFromSource<ImplicitOnClass>(Buffer().apply { write(imlClass) }) shouldBe ImplicitOnClass("foo")
        DER.decodeFromSource<ImplicitOnProperty>(Buffer().apply { write(imlProp) }) shouldBe ImplicitOnProperty("foo")
        DER.decodeFromSource<ImplicitOnBoth>(Buffer().apply { write(imlBoth) }) shouldBe ImplicitOnBoth("foo")

        shouldThrow<SerializationException> { DER.decodeFromSource<ImplicitOnProperty>(Buffer().apply { write(imlClass) }) }
        shouldThrow<SerializationException> { DER.decodeFromSource<ImplicitOnProperty>(Buffer().apply { write(imlBoth) }) }
        shouldThrow<SerializationException> { DER.decodeFromSource<ImplicitOnProperty>(Buffer().apply { write(imlNothing) }) }

        shouldThrow<SerializationException> { DER.decodeFromSource<ImplicitOnClass>(Buffer().apply { write(imlNothing) }) }
        shouldThrow<SerializationException> { DER.decodeFromSource<ImplicitOnClass>(Buffer().apply { write(imlBoth) }) }
        shouldThrow<SerializationException> { DER.decodeFromSource<ImplicitOnClass>(Buffer().apply { write(imlProp) }) }

        shouldThrow<SerializationException> { DER.decodeFromSource<ImplicitOnBoth>(Buffer().apply { write(imlProp) }) }
        shouldThrow<SerializationException> { DER.decodeFromSource<ImplicitOnBoth>(Buffer().apply { write(imlClass) }) }
        shouldThrow<SerializationException> { DER.decodeFromSource<ImplicitOnBoth>(Buffer().apply { write(imlNothing) }) }

        shouldThrow<SerializationException> { DER.decodeFromSource<NothingOnClass>(Buffer().apply { write(imlClass) }) }
        shouldThrow<SerializationException> { DER.decodeFromSource<NothingOnClass>(Buffer().apply { write(imlProp) }) }
        shouldThrow<SerializationException> { DER.decodeFromSource<NothingOnClass>(Buffer().apply { write(imlBoth) }) }

        shouldThrow<SerializationException> { DER.decodeFromSource<ImplicitOnClassWrong>(Buffer().apply { write(imlClass) }) }
        shouldThrow<SerializationException> { DER.decodeFromSource<ImplicitOnPropertyWrong>(Buffer().apply { write(imlProp) }) }
        shouldThrow<SerializationException> { DER.decodeFromSource<ImplicitOnBothWrong>(Buffer().apply { write(imlBoth) }) }
        shouldThrow<SerializationException> { DER.decodeFromSource<ImplicitOnBothWrongClass>(Buffer().apply { write(imlBoth) }) }
        shouldThrow<SerializationException> { DER.decodeFromSource<ImplicitOnBothWrongProperty>(Buffer().apply { write(imlBoth) }) }

        "Nested" {
            val nothingOnClassNested = Buffer().apply { DER.encodeToSink(

                NothingOnClassNested(NothingOnClass("foo"))
            , this) }.readByteArray()
            val nothingOnClassNestedOnClass = Buffer().apply { DER.encodeToSink(

                NothingOnClassNestedOnClass(ImplicitOnClass("foo"))
            , this) }.readByteArray()
            val nothingOnClassNestedOnProperty = Buffer().apply { DER.encodeToSink(

                NothingOnClassNestedOnProperty(NothingOnClass("foo"))
            , this) }.readByteArray()
            val nothingOnClassNestedOnPropertyOverride =
                Buffer().apply { DER.encodeToSink(

                    NothingOnClassNestedOnPropertyOverride(ImplicitOnClass("foo"))
                , this) }.readByteArray()

            nothingOnClassNested.toHexString() shouldBe "300730050c03666f6f"
            nothingOnClassNestedOnClass.toHexString() shouldBe "3009bf8a39050c03666f6f"
            nothingOnClassNestedOnProperty.toHexString() shouldBe "3009bf8a39050c03666f6f"
            nothingOnClassNestedOnPropertyOverride.toHexString() shouldBe "3009bf851a050c03666f6f"

            DER.decodeFromSource<NothingOnClassNested>(Buffer().apply { write(nothingOnClassNested) })
            DER.decodeFromSource<NothingOnClassNestedOnClass>(Buffer().apply { write(nothingOnClassNestedOnClass) })
            DER.decodeFromSource<NothingOnClassNestedOnClass>(Buffer().apply { write(nothingOnClassNestedOnProperty) })
            DER.decodeFromSource<NothingOnClassNestedOnProperty>(Buffer().apply { write(nothingOnClassNestedOnProperty) })
            DER.decodeFromSource<NothingOnClassNestedOnProperty>(Buffer().apply { write(nothingOnClassNestedOnClass) })

            DER.decodeFromSource<NothingOnClassNestedOnPropertyOverride>(Buffer().apply { write(nothingOnClassNestedOnPropertyOverride) })

            shouldThrow<SerializationException> {
                DER.decodeFromSource<NothingOnClassNested>(Buffer().apply { write(
                    nothingOnClassNestedOnClass
                ) })
            }
            shouldThrow<SerializationException> {
                DER.decodeFromSource<NothingOnClassNested>(Buffer().apply { write(nothingOnClassNestedOnProperty) })
            }
            shouldThrow<SerializationException> {
                DER.decodeFromSource<NothingOnClassNested>(Buffer().apply { write(nothingOnClassNestedOnPropertyOverride) })
            }

            shouldThrow<SerializationException> {
                DER.decodeFromSource<NothingOnClassNestedOnClass>(Buffer().apply { write(
                    nothingOnClassNested
                ) })
            }
            shouldThrow<SerializationException> {
                DER.decodeFromSource<NothingOnClassNestedOnClass>(Buffer().apply { write(nothingOnClassNestedOnPropertyOverride) })
            }

            shouldThrow<SerializationException> {
                DER.decodeFromSource<NothingOnClassNestedOnProperty>(Buffer().apply { write(nothingOnClassNested) })
            }
            shouldThrow<SerializationException> {
                DER.decodeFromSource<NothingOnClassNestedOnProperty>(Buffer().apply { write(nothingOnClassNestedOnPropertyOverride) })
            }

            shouldThrow<SerializationException> {
                DER.decodeFromSource<NothingOnClassNestedOnPropertyOverride>(Buffer().apply { write(nothingOnClassNested) })
            }
            shouldThrow<SerializationException> {
                DER.decodeFromSource<NothingOnClassNestedOnPropertyOverride>(Buffer().apply { write(nothingOnClassNestedOnProperty) })
            }
            shouldThrow<SerializationException> {
                DER.decodeFromSource<NothingOnClassNestedOnPropertyOverride>(Buffer().apply { write(nothingOnClassNestedOnClass) })
            }

            shouldThrow<SerializationException> {
                DER.decodeFromSource<NothingOnClassNestedOnClassWrong>(Buffer().apply { write(nothingOnClassNested) })
            }
            shouldThrow<SerializationException> {
                DER.decodeFromSource<NothingOnClassNestedOnClassWrong>(Buffer().apply { write(nothingOnClassNestedOnClass) })
            }
            shouldThrow<SerializationException> {
                DER.decodeFromSource<NothingOnClassNestedOnClassWrong>(Buffer().apply { write(nothingOnClassNestedOnProperty) })
            }
            shouldThrow<SerializationException> {
                DER.decodeFromSource<NothingOnClassNestedOnClassWrong>(Buffer().apply { write(nothingOnClassNestedOnPropertyOverride) })
            }

            shouldThrow<SerializationException> {
                DER.decodeFromSource<NothingOnClassNestedOnPropertyWrong>(Buffer().apply { write(nothingOnClassNested) })
            }
            shouldThrow<SerializationException> {
                DER.decodeFromSource<NothingOnClassNestedOnPropertyWrong>(Buffer().apply { write(nothingOnClassNestedOnClass) })
            }
            shouldThrow<SerializationException> {
                DER.decodeFromSource<NothingOnClassNestedOnPropertyWrong>(Buffer().apply { write(nothingOnClassNestedOnProperty) })
            }
            shouldThrow<SerializationException> {
                DER.decodeFromSource<NothingOnClassNestedOnPropertyWrong>(Buffer().apply { write(nothingOnClassNestedOnPropertyOverride) })
            }

            shouldThrow<SerializationException> {
                DER.decodeFromSource<NothingOnClassNestedOnPropertyOverrideWrong>(Buffer().apply { write(nothingOnClassNested) })
            }
            shouldThrow<SerializationException> {
                DER.decodeFromSource<NothingOnClassNestedOnPropertyOverrideWrong>(Buffer().apply { write(nothingOnClassNestedOnClass) })
            }
            shouldThrow<SerializationException> {
                DER.decodeFromSource<NothingOnClassNestedOnPropertyOverrideWrong>(Buffer().apply { write(nothingOnClassNestedOnProperty) })
            }
            shouldThrow<SerializationException> {
                DER.decodeFromSource<NothingOnClassNestedOnPropertyOverrideWrong>(Buffer().apply { write(
                    nothingOnClassNestedOnPropertyOverride
                ) })
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
