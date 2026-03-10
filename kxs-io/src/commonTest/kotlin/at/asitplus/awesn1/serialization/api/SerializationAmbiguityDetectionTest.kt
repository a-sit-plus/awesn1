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
import kotlinx.serialization.*
import kotlin.reflect.typeOf

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestAmbiguityDetection by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "Generic nullable ambiguity is rejected at runtime" {
        val ambiguous = AmbiguousNullableStringLayout("first", null, "third")
        shouldThrow<SerializationException> {
            Buffer().apply { DER.encodeToSink(ambiguous, this) }.readByteArray()
        }
        shouldThrow<SerializationException> {
            DER.decodeFromSource<AmbiguousNullableStringLayout>(Buffer().apply { write("300e0c0566697273740c057468697264".hexToByteArray()) })
        }
    }

    "Tagged nullable layouts remain valid" {
        val valueWithoutSecond = TaggedNullableStringLayout("first", null, "third")
        val valueWithSecond = TaggedNullableStringLayout("first", "second", "third")

        DER.decodeFromSource<TaggedNullableStringLayout>(Buffer().apply { write(Buffer().apply { DER.encodeToSink(valueWithoutSecond, this) }.readByteArray()) }) shouldBe valueWithoutSecond
        DER.decodeFromSource<TaggedNullableStringLayout>(Buffer().apply { write(Buffer().apply { DER.encodeToSink(valueWithSecond, this) }.readByteArray()) }) shouldBe valueWithSecond
    }

    "Consecutive nullable numeric fields are ambiguous without tags" {
        val value = ConsecutiveNumericNullables(
            longValue = 7L,
            intValue = null,
            shortValue = 3,
            byteValue = null,
            floatValue = null,
            doubleValue = 1.0
        )

        shouldThrow<SerializationException> {
            Buffer().apply { DER.encodeToSink(value, this) }.readByteArray()
        }
        shouldThrow<SerializationException> {
            DER.decodeFromSource<ConsecutiveNumericNullables>(Buffer().apply { write("3000".hexToByteArray()) })
        }
    }

    "Consecutive nullable numeric fields can be disambiguated with tags" {
        val mostlyNull = TaggedConsecutiveNumericNullables(
            longValue = null,
            intValue = 9,
            shortValue = null,
            byteValue = 2,
            floatValue = null,
            doubleValue = 3.5
        )
        val mostlySet = TaggedConsecutiveNumericNullables(
            longValue = 11L,
            intValue = 10,
            shortValue = 9,
            byteValue = 8,
            floatValue = 7.5f,
            doubleValue = 6.25
        )

        DER.decodeFromSource<TaggedConsecutiveNumericNullables>(Buffer().apply { write(
            Buffer().apply { DER.encodeToSink(
                DER.configuration.serializersModule.serializer(
                    typeOf<TaggedConsecutiveNumericNullables>()
                ), mostlyNull
            , this) }.readByteArray().also { println("!: " + it.toHexString()) }) }) shouldBe mostlyNull
        DER.decodeFromSource<TaggedConsecutiveNumericNullables>(Buffer().apply { write(
            Buffer().apply { DER.encodeToSink(
                DER.configuration.serializersModule.serializer(
                    typeOf<TaggedConsecutiveNumericNullables>()
                ), mostlySet
            , this) }.readByteArray().also { println("2: " + it.toHexString()) }) }) shouldBe mostlySet
    }

    "Consecutive nullable fields with distinct ASN.1 primitive kinds are unambiguous without tags" {
        val value = ConsecutiveDistinctNullableKinds(
            intValue = 3,
            boolValue = null,
            floatValue = 1.25f,
            stringValue = "ok"
        )
        DER.decodeFromSource<ConsecutiveDistinctNullableKinds>(Buffer().apply { write(
            Buffer().apply { DER.encodeToSink(
                DER.configuration.serializersModule.serializer(
                    typeOf<ConsecutiveDistinctNullableKinds>()
                ), value
            , this) }.readByteArray()
        ) }) shouldBe value
    }

    "Partially tagged nullable numeric fields can still be ambiguous" {
        val value = PartiallyTaggedAmbiguousNumericNullables(
            longValue = 1L,
            intValue = null,
            shortValue = 2,
            byteValue = null,
            floatValue = 3.5f,
            doubleValue = null
        )

        shouldThrow<SerializationException> {
            Buffer().apply { DER.encodeToSink(
                DER.configuration.serializersModule.serializer(typeOf<PartiallyTaggedAmbiguousNumericNullables>()),
                value
            , this) }.readByteArray()
        }
        shouldThrow<SerializationException> {
            DER.decodeFromSource<PartiallyTaggedAmbiguousNumericNullables>(Buffer().apply { write("3000".hexToByteArray()) })
        }
    }

    "Partially tagged nullable numeric fields can be unambiguous" {
        val mostlyNull = PartiallyTaggedUnambiguousNumericNullables(
            longValue = null,
            intValue = 10,
            shortValue = null,
            byteValue = 3,
            floatValue = null,
            doubleValue = 2.25
        )
        val mostlySet = PartiallyTaggedUnambiguousNumericNullables(
            longValue = 12L,
            intValue = 11,
            shortValue = 10,
            byteValue = 9,
            floatValue = 8.75f,
            doubleValue = 7.5
        )

        DER.decodeFromSource<PartiallyTaggedUnambiguousNumericNullables>(Buffer().apply { write(
            Buffer().apply { DER.encodeToSink(
                DER.configuration.serializersModule.serializer(
                    typeOf<PartiallyTaggedUnambiguousNumericNullables>()
                ), mostlyNull
            , this) }.readByteArray()
        ) }) shouldBe mostlyNull
        DER.decodeFromSource<PartiallyTaggedUnambiguousNumericNullables>(Buffer().apply { write(
            Buffer().apply { DER.encodeToSink(
                DER.configuration.serializersModule.serializer(
                    typeOf<PartiallyTaggedUnambiguousNumericNullables>()
                ), mostlySet
            , this) }.readByteArray()
        ) }) shouldBe mostlySet
    }

    "Tag class is considered for ambiguity disambiguation" {
        val withoutTagged = ContextSpecificVsUniversalInt(null, 7)
        val withTagged = ContextSpecificVsUniversalInt(5, 7)

        DER.decodeFromSource<ContextSpecificVsUniversalInt>(Buffer().apply { write(
            Buffer().apply { DER.encodeToSink(
                DER.configuration.serializersModule.serializer(
                    typeOf<ContextSpecificVsUniversalInt>()
                ), withoutTagged
            , this) }.readByteArray()
        ) }) shouldBe withoutTagged
        DER.decodeFromSource<ContextSpecificVsUniversalInt>(Buffer().apply { write(
            Buffer().apply { DER.encodeToSink(
                DER.configuration.serializersModule.serializer(
                    typeOf<ContextSpecificVsUniversalInt>()
                ), withTagged
            , this) }.readByteArray()
        ) }) shouldBe withTagged
    }

    "Class-level tags participate in ambiguity detection" {
        val ambiguous = NullablePlainIntBoxThenPlainIntBox(
            first = null,
            second = PlainIntBox(7)
        )
        shouldThrow<SerializationException> {
            Buffer().apply { DER.encodeToSink(
                DER.configuration.serializersModule.serializer(typeOf<NullablePlainIntBoxThenPlainIntBox>()),
                ambiguous
            , this) }.readByteArray()
        }
        shouldThrow<SerializationException> {
            DER.decodeFromSource<NullablePlainIntBoxThenPlainIntBox>(Buffer().apply { write("3000".hexToByteArray()) })
        }

        val taggedWithoutFirst = NullableClassTaggedIntBoxes(
            first = null,
            second = ClassTaggedIntBoxB(7)
        )
        val taggedWithFirst = NullableClassTaggedIntBoxes(
            first = ClassTaggedIntBoxA(5),
            second = ClassTaggedIntBoxB(7)
        )

        DER.decodeFromSource<NullableClassTaggedIntBoxes>(Buffer().apply { write(
            Buffer().apply { DER.encodeToSink(
                DER.configuration.serializersModule.serializer(
                    typeOf<NullableClassTaggedIntBoxes>()
                ), taggedWithoutFirst
            , this) }.readByteArray()
        ) }) shouldBe taggedWithoutFirst
        DER.decodeFromSource<NullableClassTaggedIntBoxes>(Buffer().apply { write(
            Buffer().apply { DER.encodeToSink(
                DER.configuration.serializersModule.serializer(
                    typeOf<NullableClassTaggedIntBoxes>()
                ), taggedWithFirst
            , this) }.readByteArray()
        ) }) shouldBe taggedWithFirst
    }

    "Mixed property and class-level tags can still be ambiguous" {
        val ambiguous = NullableMixedTagLayeringStillAmbiguous(
            first = null,
            second = ClassImplicitIntBoxB(9)
        )
        shouldThrow<SerializationException> {
            Buffer().apply { DER.encodeToSink(
                DER.configuration.serializersModule.serializer(typeOf<NullableMixedTagLayeringStillAmbiguous>()),
                ambiguous
            , this) }.readByteArray()
        }
        shouldThrow<SerializationException> {
            DER.decodeFromSource<NullableMixedTagLayeringStillAmbiguous>(Buffer().apply { write("3000".hexToByteArray()) })
        }
    }

    "Mixed property and class-level tags can disambiguate nullable fields" {
        val withoutFirst = NullableMixedTagLayeringDisambiguated(
            first = null,
            second = ClassImplicitIntBoxB(9)
        )
        val withFirst = NullableMixedTagLayeringDisambiguated(
            first = ClassImplicitIntBoxA(3),
            second = ClassImplicitIntBoxB(9)
        )

        DER.decodeFromSource<NullableMixedTagLayeringDisambiguated>(Buffer().apply { write(
            Buffer().apply { DER.encodeToSink(
                DER.configuration.serializersModule.serializer(
                    typeOf<NullableMixedTagLayeringDisambiguated>()
                ), withoutFirst
            , this) }.readByteArray()
        ) }) shouldBe withoutFirst
        DER.decodeFromSource<NullableMixedTagLayeringDisambiguated>(Buffer().apply { write(
            Buffer().apply { DER.encodeToSink(
                DER.configuration.serializersModule.serializer(
                    typeOf<NullableMixedTagLayeringDisambiguated>()
                ), withFirst
            , this) }.readByteArray()
        ) }) shouldBe withFirst
    }

    "Property implicit and class explicit layering works with nullable fields" {
        val withoutFirst = NullablePropertyImplicitClassExplicit(
            first = null,
            second = ClassExplicitIntBox(5)
        )
        val withFirst = NullablePropertyImplicitClassExplicit(
            first = ClassExplicitIntBox(4),
            second = ClassExplicitIntBox(5)
        )

        DER.decodeFromSource<NullablePropertyImplicitClassExplicit>(Buffer().apply { write(
            Buffer().apply { DER.encodeToSink(
                DER.configuration.serializersModule.serializer(
                    typeOf<NullablePropertyImplicitClassExplicit>()
                ), withoutFirst
            , this) }.readByteArray()
        ) }) shouldBe withoutFirst
        DER.decodeFromSource<NullablePropertyImplicitClassExplicit>(Buffer().apply { write(
            Buffer().apply { DER.encodeToSink(
                DER.configuration.serializersModule.serializer(
                    typeOf<NullablePropertyImplicitClassExplicit>()
                ), withFirst
            , this) }.readByteArray()
        ) }) shouldBe withFirst
    }

    "explicitNulls=true removes omission ambiguity for nullable properties" {
        val derExplicitNulls = DER { explicitNulls = true }

        val ambiguous = NullableIntThenIntAmbiguous(
            first = null,
            second = 7
        )
        shouldThrow<SerializationException> {
            Buffer().apply { DER.encodeToSink(
                DER.configuration.serializersModule.serializer(typeOf<NullableIntThenIntAmbiguous>()),
                ambiguous
            , this) }.readByteArray()
        }
        shouldThrow<SerializationException> {
            DER.decodeFromSource<NullableIntThenIntAmbiguous>(Buffer().apply { write("3000".hexToByteArray()) })
        }

        val explicitNullsEncodedNull = NullableIntThenIntAmbiguous(
            first = null,
            second = 7
        )
        val explicitNullsEncodedSet = NullableIntThenIntAmbiguous(
            first = 5,
            second = 7
        )

        derExplicitNulls.decodeFromSource<NullableIntThenIntAmbiguous>(Buffer().apply { write(
            Buffer().apply { derExplicitNulls.encodeToSink(
                derExplicitNulls.configuration.serializersModule.serializer(typeOf<NullableIntThenIntAmbiguous>()),
                explicitNullsEncodedNull
            , this) }.readByteArray()
        ) }) shouldBe explicitNullsEncodedNull
        derExplicitNulls.decodeFromSource<NullableIntThenIntAmbiguous>(Buffer().apply { write(
            Buffer().apply { derExplicitNulls.encodeToSink(
                derExplicitNulls.configuration.serializersModule.serializer(typeOf<NullableIntThenIntAmbiguous>()),
                explicitNullsEncodedSet
            , this) }.readByteArray()
        ) }) shouldBe explicitNullsEncodedSet
    }

    "explicitNulls=true also disambiguates nullable object omission layouts" {
        val derExplicitNulls = DER { explicitNulls = true }

        val ambiguous = NullablePlainObjectThenPlainIntBox(
            first = null,
            second = PlainIntBox(7)
        )
        shouldThrow<SerializationException> {
            Buffer().apply { DER.encodeToSink(
                DER.configuration.serializersModule.serializer(typeOf<NullablePlainObjectThenPlainIntBox>()),
                ambiguous
            , this) }.readByteArray()
        }
        shouldThrow<SerializationException> {
            DER.decodeFromSource<NullablePlainObjectThenPlainIntBox>(Buffer().apply { write("3000".hexToByteArray()) })
        }

        val explicitNullsEncodedNull = NullablePlainObjectThenPlainIntBox(
            first = null,
            second = PlainIntBox(7)
        )
        val explicitNullsEncodedSet = NullablePlainObjectThenPlainIntBox(
            first = PlainObject,
            second = PlainIntBox(7)
        )

        derExplicitNulls.decodeFromSource<NullablePlainObjectThenPlainIntBox>(Buffer().apply { write(
            Buffer().apply { derExplicitNulls.encodeToSink(
                derExplicitNulls.configuration.serializersModule.serializer(typeOf<NullablePlainObjectThenPlainIntBox>()),
                explicitNullsEncodedNull
            , this) }.readByteArray()
        ) }) shouldBe explicitNullsEncodedNull
        derExplicitNulls.decodeFromSource<NullablePlainObjectThenPlainIntBox>(Buffer().apply { write(
            Buffer().apply { derExplicitNulls.encodeToSink(
                derExplicitNulls.configuration.serializersModule.serializer(typeOf<NullablePlainObjectThenPlainIntBox>()),
                explicitNullsEncodedSet
            , this) }.readByteArray()
        ) }) shouldBe explicitNullsEncodedSet
    }
}

@Serializable
data class AmbiguousNullableStringLayout(
    val first: String,
    val second: String?,
    val third: String,
)

@Serializable
data class TaggedNullableStringLayout(
    val first: String,
    @Asn1Tag(tagNumber = 0u)
    val second: String?,
    val third: String,
)

@Serializable
data class ConsecutiveNumericNullables(
    val longValue: Long?,
    val intValue: Int?,
    val shortValue: Short?,
    val byteValue: Byte?,
    val floatValue: Float?,
    val doubleValue: Double?,
)

@Serializable
data class TaggedConsecutiveNumericNullables(
    @Asn1Tag(tagNumber = 10u)
    val longValue: Long?,
    @Asn1Tag(tagNumber = 11u)
    val intValue: Int?,
    @Asn1Tag(tagNumber = 12u)
    val shortValue: Short?,
    @Asn1Tag(tagNumber = 13u)
    val byteValue: Byte?,
    @Asn1Tag(tagNumber = 14u)
    val floatValue: Float?,
    @Asn1Tag(tagNumber = 15u)
    val doubleValue: Double?,
)

@Serializable
data class ConsecutiveDistinctNullableKinds(
    val intValue: Int?,
    val boolValue: Boolean?,
    val floatValue: Float?,
    val stringValue: String?,
)

@Serializable
data class PartiallyTaggedAmbiguousNumericNullables(
    @Asn1Tag(tagNumber = 20u)
    val longValue: Long?,
    val intValue: Int?,
    @Asn1Tag(tagNumber = 21u)
    val shortValue: Short?,
    val byteValue: Byte?,
    @Asn1Tag(tagNumber = 22u)
    val floatValue: Float?,
    val doubleValue: Double?,
)

@Serializable
data class PartiallyTaggedUnambiguousNumericNullables(
    @Asn1Tag(tagNumber = 30u)
    val longValue: Long?,
    @Asn1Tag(tagNumber = 31u)
    val intValue: Int?,
    val shortValue: Short?,
    @Asn1Tag(tagNumber = 32u)
    val byteValue: Byte?,
    @Asn1Tag(tagNumber = 33u)
    val floatValue: Float?,
    val doubleValue: Double?,
)

@Serializable
data class ContextSpecificVsUniversalInt(
    @Asn1Tag(tagNumber = 2u)
    val maybeTaggedInt: Int?,
    val plainInt: Int,
)

@Serializable
data class PlainIntBox(val value: Int)

@Serializable
@Asn1Tag(tagNumber = 80u)
data class ClassTaggedIntBoxA(val value: Int)

@Serializable
@Asn1Tag(tagNumber = 81u)
data class ClassTaggedIntBoxB(val value: Int)

@Serializable
data class NullablePlainIntBoxThenPlainIntBox(
    val first: PlainIntBox?,
    val second: PlainIntBox,
)

@Serializable
data class NullableClassTaggedIntBoxes(
    val first: ClassTaggedIntBoxA?,
    val second: ClassTaggedIntBoxB,
)

@Serializable
@Asn1Tag(tagNumber = 90u)
data class ClassImplicitIntBoxA(val value: Int)

@Serializable
@Asn1Tag(tagNumber = 91u)
data class ClassImplicitIntBoxB(val value: Int)

@Serializable
data class NullableMixedTagLayeringStillAmbiguous(
    @Asn1Tag(tagNumber = 100u)
    val first: ClassImplicitIntBoxA?,
    @Asn1Tag(tagNumber = 100u)
    val second: ClassImplicitIntBoxB,
)

@Serializable
data class NullableMixedTagLayeringDisambiguated(
    @Asn1Tag(tagNumber = 100u)
    val first: ClassImplicitIntBoxA?,
    @Asn1Tag(tagNumber = 101u)
    val second: ClassImplicitIntBoxB,
)

@Serializable
@Asn1Tag(tagNumber = 110u)
data class ClassExplicitIntBox(val value: Int)

@Serializable
data class NullablePropertyImplicitClassExplicit(
    @Asn1Tag(tagNumber = 111u)
    val first: ClassExplicitIntBox?,
    @Asn1Tag(tagNumber = 112u)
    val second: ClassExplicitIntBox,
)

@Serializable
data class NullableIntThenIntAmbiguous(
    val first: Int?,
    val second: Int,
)

@Serializable
object PlainObject

@Serializable
data class NullablePlainObjectThenPlainIntBox(
    val first: PlainObject?,
    val second: PlainIntBox,
)
