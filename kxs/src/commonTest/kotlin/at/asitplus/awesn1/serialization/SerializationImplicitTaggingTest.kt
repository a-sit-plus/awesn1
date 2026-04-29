package at.asitplus.awesn1.serialization

import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldEndWith
import io.kotest.matchers.string.shouldStartWith
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlin.jvm.JvmInline

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

        "Inline value class with UByte backing preserves class tag" {
            val uByteBacked = DER.encodeToByteArray(ImplicitValueClassUByte(0x23u))
            val byteBacked = DER.encodeToByteArray(ImplicitValueClassByte(0x23))

            uByteBacked.toHexString() shouldBe "d20123"
            byteBacked.toHexString() shouldBe "d20123"

            DER.decodeFromByteArray<ImplicitValueClassUByte>(uByteBacked) shouldBe ImplicitValueClassUByte(0x23u)
            DER.decodeFromByteArray<ImplicitValueClassByte>(byteBacked) shouldBe ImplicitValueClassByte(0x23)
        }

        "Inline value classes with unsigned primitive backing preserve class tag" {
            DER.encodeToByteArray(ImplicitValueClassUByte(0x23u)).toHexString() shouldBe "d20123"
            DER.encodeToByteArray(ImplicitValueClassUShort(0x0123u)).toHexString() shouldBe "d2020123"
            DER.encodeToByteArray(ImplicitValueClassUInt(0x01234567u)).toHexString() shouldBe "d20401234567"
            DER.encodeToByteArray(ImplicitValueClassULong(0x0123456789abcdefu)).toHexString() shouldBe
                    "d2080123456789abcdef"

            DER.decodeFromByteArray<ImplicitValueClassUByte>("d20123".hexToByteArray()) shouldBe
                    ImplicitValueClassUByte(0x23u)
            DER.decodeFromByteArray<ImplicitValueClassUShort>("d2020123".hexToByteArray()) shouldBe
                    ImplicitValueClassUShort(0x0123u)
            DER.decodeFromByteArray<ImplicitValueClassUInt>("d20401234567".hexToByteArray()) shouldBe
                    ImplicitValueClassUInt(0x01234567u)
            DER.decodeFromByteArray<ImplicitValueClassULong>("d2080123456789abcdef".hexToByteArray()) shouldBe
                    ImplicitValueClassULong(0x0123456789abcdefu)
        }

        "Inline value class with custom nested inline backing preserves class tag" {
            val encoded = DER.encodeToByteArray(ImplicitNestedInline(InlineLayer3(InlineLayer2(InlineLayer1(0x23)))))

            encoded.toHexString() shouldBe "d20123"
            DER.decodeFromByteArray<ImplicitNestedInline>(encoded) shouldBe
                    ImplicitNestedInline(InlineLayer3(InlineLayer2(InlineLayer1(0x23))))
        }

        "Implicitly tagged inline class overrides implicitly tagged wrapped class" {
            val value = InlineTaggedOuterClassTaggedInner(ClassTaggedInner(0x23))
            val encoded = DER.encodeToByteArray(value)

            encoded.toHexString() shouldBe "f203020123"
            DER.decodeFromByteArray<InlineTaggedOuterClassTaggedInner>(encoded) shouldBe value
            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<InlineTaggedOuterClassTaggedInner>("f303020123".hexToByteArray())
            }
        }

        "Outermost inline class tag wins across multiple tagged inline layers" {
            val value = TaggedInlineLayer6(
                TaggedInlineLayer5(
                    TaggedInlineLayer4(
                        TaggedInlineLayer3(
                            TaggedInlineLayer2(
                                TaggedInlineLayer1(0x23)
                            )
                        )
                    )
                )
            )
            val encoded = DER.encodeToByteArray(value)

            encoded.toHexString() shouldBe "d20123"
            DER.decodeFromByteArray<TaggedInlineLayer6>(encoded) shouldBe value
            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<TaggedInlineLayer6>("d30123".hexToByteArray())
            }
            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<TaggedInlineLayer6>("d70123".hexToByteArray())
            }
        }

        "Inline value class with six nested inline layers preserves class tag" {
            val value = ImplicitSixLayerInline(
                InlineLayer6(InlineLayer5(InlineLayer4(InlineLayer3(InlineLayer2(InlineLayer1(0x23))))))
            )
            val encoded = DER.encodeToByteArray(value)

            encoded.toHexString() shouldBe "d20123"
            DER.decodeFromByteArray<ImplicitSixLayerInline>(encoded) shouldBe value
        }

        "Inline value class with six nested inline layers and UByte core preserves class tag" {
            val value = ImplicitSixLayerUByteInline(
                InlineUByteLayer6(
                    InlineUByteLayer5(
                        InlineUByteLayer4(
                            InlineUByteLayer3(
                                InlineUByteLayer2(
                                    InlineUByteLayer1(0x23u)
                                )
                            )
                        )
                    )
                )
            )
            val encoded = DER.encodeToByteArray(value)

            encoded.toHexString() shouldBe "d20123"
            DER.decodeFromByteArray<ImplicitSixLayerUByteInline>(encoded) shouldBe value
        }

        "Value class Byte backing property tag is rejected" {
            val classTagged = ValueClassByteClassTagged(0x23)
            val propertyTagged = ValueClassBytePropertyTagged(0x23)
            val classAndPropertyTagged = ValueClassByteClassAndPropertyTagged(0x23)

            DER.encodeToByteArray(classTagged).toHexString() shouldBe "d20123"
            DER.decodeFromByteArray<ValueClassByteClassTagged>("d20123".hexToByteArray()) shouldBe classTagged


            shouldThrow<SerializationException> {
                DER.encodeToByteArray(propertyTagged)
            }.message.let {
                it shouldStartWith "@Asn1Tag on inline/value class backing property is not supported"
                it shouldEndWith "Annotate the inline/value class itself instead."
            }

            shouldThrow<SerializationException> {
                DER.encodeToByteArray(classAndPropertyTagged)
            }.message.let {
                it shouldStartWith "@Asn1Tag on inline/value class backing property is not supported"
                it shouldEndWith "Annotate the inline/value class itself instead."
            }

            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<ValueClassByteClassTagged>("020123".hexToByteArray())
            }.message shouldEndWith "Asn1TagMismatchException: Expected tag PRIVATE 18 (=D2), is: 2 (=02) (INTEGER)"

            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<ValueClassBytePropertyTagged>("020123".hexToByteArray())
            }.message.let {
                it shouldStartWith "@Asn1Tag on inline/value class backing property is not supported"
                it shouldEndWith "Annotate the inline/value class itself instead."
            }

            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<ValueClassBytePropertyTagged>("d30123".hexToByteArray())
            }.message.let {
                it shouldStartWith "@Asn1Tag on inline/value class backing property is not supported"
                it shouldEndWith "Annotate the inline/value class itself instead."
            }

            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<ValueClassByteClassAndPropertyTagged>("d20123".hexToByteArray())
            }.message.let {
                it shouldStartWith "@Asn1Tag on inline/value class backing property is not supported"
                it shouldEndWith "Annotate the inline/value class itself instead."
            }

            shouldThrow<SerializationException> {
                DER.decodeFromByteArray<ValueClassByteClassAndPropertyTagged>("d30123".hexToByteArray())
            }.message.let {
                it shouldStartWith "@Asn1Tag on inline/value class backing property is not supported"
                it shouldEndWith "Annotate the inline/value class itself instead."
            }
        }

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
@Asn1Tag(tagNumber = 1337u, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC)
data class ImplicitOnClass(val a: String)

@Serializable
@Asn1Tag(tagNumber = 7331u, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC)
data class ImplicitOnClassWrong(val a: String)

@Serializable
data class ImplicitOnProperty(@Asn1Tag(tagNumber = 1338u, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC) val a: String)

@Serializable
data class ImplicitOnPropertyWrong(@Asn1Tag(tagNumber = 8331u, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC) val a: String)

@Serializable
@Asn1Tag(tagNumber = 1337u, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC)
data class ImplicitOnBoth(@Asn1Tag(tagNumber = 1338u, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC) val a: String)

@Serializable
@Asn1Tag(tagNumber = 73331u, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC)
data class ImplicitOnBothWrong(@Asn1Tag(tagNumber = 8331u, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC) val a: String)

@Serializable
@Asn1Tag(tagNumber = 7331u, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC)
data class ImplicitOnBothWrongClass(@Asn1Tag(tagNumber = 1338u, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC) val a: String)

@Serializable
@Asn1Tag(tagNumber = 1337u, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC)
data class ImplicitOnBothWrongProperty(
    @Asn1Tag(
        tagNumber = 8331u,
        tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC
    ) val a: String
)

@Asn1Tag(18u, Asn1TagClass.PRIVATE)
@JvmInline
@Serializable
value class ImplicitValueClassUByte(val byte: UByte)

@Asn1Tag(18u, Asn1TagClass.PRIVATE)
@JvmInline
@Serializable
value class ImplicitValueClassUShort(val value: UShort)

@Asn1Tag(18u, Asn1TagClass.PRIVATE)
@JvmInline
@Serializable
value class ImplicitValueClassUInt(val value: UInt)

@Asn1Tag(18u, Asn1TagClass.PRIVATE)
@JvmInline
@Serializable
value class ImplicitValueClassULong(val value: ULong)

@Asn1Tag(18u, Asn1TagClass.PRIVATE)
@JvmInline
@Serializable
value class ImplicitValueClassByte(val byte: Byte)

@Asn1Tag(18u, Asn1TagClass.PRIVATE)
@JvmInline
@Serializable
value class ImplicitNestedInline(val value: InlineLayer3)

@Asn1Tag(18u, Asn1TagClass.PRIVATE)
@JvmInline
@Serializable
value class ImplicitSixLayerInline(val value: InlineLayer6)

@Asn1Tag(18u, Asn1TagClass.PRIVATE)
@JvmInline
@Serializable
value class ImplicitSixLayerUByteInline(val value: InlineUByteLayer6)

@Asn1Tag(19u, Asn1TagClass.PRIVATE)
@JvmInline
@Serializable
value class TaggedInlineLayer1(val value: Byte)

@Asn1Tag(20u, Asn1TagClass.PRIVATE)
@JvmInline
@Serializable
value class TaggedInlineLayer2(val value: TaggedInlineLayer1)

@Asn1Tag(21u, Asn1TagClass.PRIVATE)
@JvmInline
@Serializable
value class TaggedInlineLayer3(val value: TaggedInlineLayer2)

@Asn1Tag(22u, Asn1TagClass.PRIVATE)
@JvmInline
@Serializable
value class TaggedInlineLayer4(val value: TaggedInlineLayer3)

@Asn1Tag(23u, Asn1TagClass.PRIVATE)
@JvmInline
@Serializable
value class TaggedInlineLayer5(val value: TaggedInlineLayer4)

@Asn1Tag(18u, Asn1TagClass.PRIVATE)
@JvmInline
@Serializable
value class TaggedInlineLayer6(val value: TaggedInlineLayer5)

@JvmInline
@Serializable
value class InlineLayer1(val value: Byte)

@JvmInline
@Serializable
value class InlineLayer2(val value: InlineLayer1)

@JvmInline
@Serializable
value class InlineLayer3(val value: InlineLayer2)

@JvmInline
@Serializable
value class InlineLayer4(val value: InlineLayer3)

@JvmInline
@Serializable
value class InlineLayer5(val value: InlineLayer4)

@JvmInline
@Serializable
value class InlineLayer6(val value: InlineLayer5)

@JvmInline
@Serializable
value class InlineUByteLayer1(val value: UByte)

@JvmInline
@Serializable
value class InlineUByteLayer2(val value: InlineUByteLayer1)

@JvmInline
@Serializable
value class InlineUByteLayer3(val value: InlineUByteLayer2)

@JvmInline
@Serializable
value class InlineUByteLayer4(val value: InlineUByteLayer3)

@JvmInline
@Serializable
value class InlineUByteLayer5(val value: InlineUByteLayer4)

@JvmInline
@Serializable
value class InlineUByteLayer6(val value: InlineUByteLayer5)

@Asn1Tag(18u, Asn1TagClass.PRIVATE)
@JvmInline
@Serializable
value class ValueClassByteClassTagged(val value: Byte)

@JvmInline
@Serializable
value class ValueClassBytePropertyTagged(@Asn1Tag(19u, Asn1TagClass.PRIVATE) val value: Byte)

@Asn1Tag(18u, Asn1TagClass.PRIVATE)
@JvmInline
@Serializable
value class ValueClassByteClassAndPropertyTagged(@Asn1Tag(19u, Asn1TagClass.PRIVATE) val value: Byte)

@Asn1Tag(19u, Asn1TagClass.PRIVATE)
@Serializable
data class ClassTaggedInner(val value: Byte)

@Asn1Tag(18u, Asn1TagClass.PRIVATE)
@JvmInline
@Serializable
value class InlineTaggedOuterClassTaggedInner(val value: ClassTaggedInner)

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
        tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC
    ) val a: NothingOnClass
)

@Serializable
data class NothingOnClassNestedOnPropertyWrong(
    @Asn1Tag(
        tagNumber = 333u,
        tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC
    ) val a: NothingOnClass
)

@Serializable
data class NothingOnClassNestedOnPropertyOverride(
    @Asn1Tag(
        tagNumber = 666u,
        tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC,
    ) val a: ImplicitOnClass
)

@Serializable
data class NothingOnClassNestedOnPropertyOverrideWrong(
    @Asn1Tag(
        tagNumber = 999u,
        tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC,
    ) val a: ImplicitOnClass
)
