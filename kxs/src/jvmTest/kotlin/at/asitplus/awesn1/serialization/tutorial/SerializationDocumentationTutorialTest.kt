package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.Identifiable
import at.asitplus.awesn1.Asn1Decodable
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Encodable
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.Asn1Set
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.docs.emitAsn1JsSample
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.decodeFromDer
import at.asitplus.awesn1.encoding.decodeToInt
import at.asitplus.awesn1.encoding.encodeToDer
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.modules.SerializersModule
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

// --8<-- [start:kxs-baseline-definitions]
@Serializable
private data class TutorialDocPerson(
    val name: String,
    val age: Int,
)
// --8<-- [end:kxs-baseline-definitions]

private fun baselineRoundTrip(): Pair<ByteArray, TutorialDocPerson> {
    // --8<-- [start:kxs-baseline-roundtrip]
    val value = TutorialDocPerson(name = "A", age = 5)
    val der = DER.encodeToByteArray(value)
    check(der.toHexString() == "30060c0141020105") /* (1)! */
    // --8<-- [end:kxs-baseline-roundtrip]
    return der to DER.decodeFromByteArray(der)
}

// --8<-- [start:kxs-tag-override-definitions]
@Serializable
private data class TutorialDocTaggedInt(
    @Asn1Tag(
        tagNumber = 0u,
        tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
        constructed = Asn1ConstructedBit.PRIMITIVE,
    )
    val value: Int,
)
// --8<-- [end:kxs-tag-override-definitions]

private fun tagOverrideRoundTrip(): Pair<ByteArray, TutorialDocTaggedInt> {
    // --8<-- [start:kxs-tag-override-roundtrip]
    val value = TutorialDocTaggedInt(value = 5)
    val der = DER.encodeToByteArray(value)
    check(der.toHexString() == "3003800105") /* (1)! */
    // --8<-- [end:kxs-tag-override-roundtrip]
    return der to DER.decodeFromByteArray(der)
}

// --8<-- [start:kxs-explicit-wrapper-definitions]
@Serializable
private data class TutorialDocExplicitCarrier(
    @Asn1Tag(
        tagNumber = 0u,
        tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
        constructed = Asn1ConstructedBit.CONSTRUCTED,
    )
    val wrapped: ExplicitlyTagged<Int>,
)
// --8<-- [end:kxs-explicit-wrapper-definitions]

private fun explicitRoundTrip(): Pair<ByteArray, TutorialDocExplicitCarrier> {
    // --8<-- [start:kxs-explicit-wrapper-roundtrip]
    val value = TutorialDocExplicitCarrier(wrapped = ExplicitlyTagged(5))
    val der = DER.encodeToByteArray(value)
    check(der.toHexString() == "3005a003020105") /* (1)! */
    // --8<-- [end:kxs-explicit-wrapper-roundtrip]
    return der to DER.decodeFromByteArray(der)
}

// --8<-- [start:kxs-choice-definitions]
@Serializable
private sealed interface TutorialDocChoice

@Serializable
private data class TutorialDocChoiceInt(
    val value: Int,
) : TutorialDocChoice

@Serializable
@Asn1Tag(1337u)
private data class TutorialDocChoiceBool(
    val value: Boolean,
) : TutorialDocChoice
// --8<-- [end:kxs-choice-definitions]

private fun choiceRoundTrip(value: TutorialDocChoice): Pair<ByteArray, TutorialDocChoice> {
    // --8<-- [start:kxs-choice-roundtrip]
    val der = DER.encodeToByteArray(value)
    val derHex = der.toHexString()
    when (value) {
        is TutorialDocChoiceInt -> check(derHex == "3003020107") /* (1)! */
        is TutorialDocChoiceBool -> check(derHex == "bf8a39030101ff") /* (2)! */
    }
    // --8<-- [end:kxs-choice-roundtrip]
    return der to DER.decodeFromByteArray(der)
}

// --8<-- [start:kxs-choice-primitive-definitions]
@Serializable
private sealed interface TutorialDocPrimitiveChoice

@Serializable
@JvmInline
private value class TutorialDocPrimitiveChoiceInt(
    val value: Int,
) : TutorialDocPrimitiveChoice

@Serializable
@JvmInline
@Asn1Tag(
    tagNumber = 0u,
    tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
    constructed = Asn1ConstructedBit.PRIMITIVE,
)
private value class TutorialDocPrimitiveChoiceBool(
    val value: Boolean,
) : TutorialDocPrimitiveChoice

@Serializable
@JvmInline
private value class TutorialDocPrimitiveChoiceText(
    val value: String,
) : TutorialDocPrimitiveChoice
// --8<-- [end:kxs-choice-primitive-definitions]

private fun primitiveChoiceRoundTrip(value: TutorialDocPrimitiveChoice): Pair<ByteArray, TutorialDocPrimitiveChoice> {
    // --8<-- [start:kxs-choice-primitive-roundtrip]
    val der = DER.encodeToByteArray(value)
    val derHex = der.toHexString()
    when (value) {
        is TutorialDocPrimitiveChoiceInt -> check(derHex == /* (1)! */"020107")
        is TutorialDocPrimitiveChoiceBool -> check(derHex == /* (2)! */"8001ff")
        is TutorialDocPrimitiveChoiceText -> check(derHex == /* (3)! */"0c0141")
    }
    // --8<-- [end:kxs-choice-primitive-roundtrip]
    return der to DER.decodeFromByteArray(der)
}

// --8<-- [start:kxs-format-options-definitions]
@Serializable
private data class TutorialDocNullableInt(
    val value: Int?,
)

@Serializable
private data class TutorialDocDefaults(
    val first: Int = 1,
    val second: Boolean = true,
)
// --8<-- [end:kxs-format-options-definitions]

private fun explicitNullsRoundTrip(): Pair<ByteArray, TutorialDocNullableInt> {
    // --8<-- [start:kxs-format-options-explicit-nulls-roundtrip]
    val format = DER { explicitNulls = true }
    val value = TutorialDocNullableInt(value = null)
    val der = format.encodeToByteArray(value)
    check(der.toHexString() == "30020500") /* (1)! */
    // --8<-- [end:kxs-format-options-explicit-nulls-roundtrip]
    return der to format.decodeFromByteArray(der)
}

private fun encodeDefaultsRoundTrip(): Pair<ByteArray, TutorialDocDefaults> {
    // --8<-- [start:kxs-format-options-encode-defaults-roundtrip]
    val format = DER { encodeDefaults = false }
    val value = TutorialDocDefaults()
    val der = format.encodeToByteArray(value)
    check(der.toHexString() == "3000") /* (2)! */
    // --8<-- [end:kxs-format-options-encode-defaults-roundtrip]
    return der to format.decodeFromByteArray(der)
}

// --8<-- [start:kxs-leading-tags-non-null-definitions]
@Serializable
private data class TutorialDocThreeNames(
    val first: String,
    val middle: String,
    val last: String,
)
// --8<-- [end:kxs-leading-tags-non-null-definitions]

private fun nonNullableNamesRoundTrip(): Pair<ByteArray, TutorialDocThreeNames> {
    // --8<-- [start:kxs-leading-tags-non-null-roundtrip]
    val value = TutorialDocThreeNames("A", "B", "C")
    val der = DER.encodeToByteArray(value)
    check(der.toHexString() == "30090c01410c01420c0143") /* (1)! */
    // --8<-- [end:kxs-leading-tags-non-null-roundtrip]
    return der to DER.decodeFromByteArray(der)
}

// --8<-- [start:kxs-leading-tags-explicit-nulls-definitions]
@Serializable
private data class TutorialDocThreeNullableNames(
    val first: String?,
    val middle: String?,
    val last: String?,
)
// --8<-- [end:kxs-leading-tags-explicit-nulls-definitions]

private fun nullableNamesWithExplicitNullsRoundTrip(): Pair<ByteArray, TutorialDocThreeNullableNames> {
    // --8<-- [start:kxs-leading-tags-explicit-nulls-roundtrip]
    val codec = DER { explicitNulls = true }
    val value = TutorialDocThreeNullableNames("A", null, "C")
    val der = codec.encodeToByteArray(value)
    check(der.toHexString() == "30080c014105000c0143") /* (1)! */
    // --8<-- [end:kxs-leading-tags-explicit-nulls-roundtrip]
    return der to codec.decodeFromByteArray(der)
}

private fun nullableNamesWithOmittedNullsAreRejected() {
    // --8<-- [start:kxs-leading-tags-ambiguous-null-omission-roundtrip]
    val value = TutorialDocThreeNullableNames("A", null, "C")
    shouldThrow<SerializationException> {
        DER.encodeToByteArray(value) /* (1)! */
    }
    // --8<-- [end:kxs-leading-tags-ambiguous-null-omission-roundtrip]
}

// --8<-- [start:kxs-leading-tags-implicit-tagging-definitions]
@Serializable
private data class TutorialDocTaggedNullableNames(
    @Asn1Tag(0u, tagClass = Asn1TagClass.CONTEXT_SPECIFIC, constructed = Asn1ConstructedBit.PRIMITIVE)
    val first: String?,
    @Asn1Tag(1u, tagClass = Asn1TagClass.CONTEXT_SPECIFIC, constructed = Asn1ConstructedBit.PRIMITIVE)
    val middle: String?,
    @Asn1Tag(2u, tagClass = Asn1TagClass.CONTEXT_SPECIFIC, constructed = Asn1ConstructedBit.PRIMITIVE)
    val last: String?,
)
// --8<-- [end:kxs-leading-tags-implicit-tagging-definitions]

private fun nullableNamesWithImplicitTagsRoundTrip(): Pair<ByteArray, TutorialDocTaggedNullableNames> {
    // --8<-- [start:kxs-leading-tags-implicit-tagging-roundtrip]
    val value = TutorialDocTaggedNullableNames("A", null, "C")
    val der = DER.encodeToByteArray(value)
    check(der.toHexString() == "3006800141820143") /* (1)! */
    // --8<-- [end:kxs-leading-tags-implicit-tagging-roundtrip]
    return der to DER.decodeFromByteArray(der)
}

// --8<-- [start:kxs-leading-tags-custom-ambiguous-definitions]
@Serializable(with = TutorialDocComplexLeftSerializer::class)
private data class TutorialDocComplexLeft(val value: Int)

@Serializable(with = TutorialDocComplexRightSerializer::class)
private data class TutorialDocComplexRight(val value: Int)

@Serializable
private data class TutorialDocCustomComplexAmbiguous(
    val left: TutorialDocComplexLeft?,
    val right: TutorialDocComplexRight?,
)

private object TutorialDocComplexLeftSerializer : KSerializer<TutorialDocComplexLeft> {
    @Serializable
    private data class Surrogate(val value: Int)

    override val descriptor: SerialDescriptor = Surrogate.serializer().descriptor

    override fun serialize(encoder: Encoder, value: TutorialDocComplexLeft) {
        encoder.encodeSerializableValue(Surrogate.serializer(), Surrogate(value.value))
    }

    override fun deserialize(decoder: Decoder): TutorialDocComplexLeft =
        TutorialDocComplexLeft(decoder.decodeSerializableValue(Surrogate.serializer()).value)
}

private object TutorialDocComplexRightSerializer : KSerializer<TutorialDocComplexRight> {
    @Serializable
    private data class Surrogate(val value: Int)

    override val descriptor: SerialDescriptor = Surrogate.serializer().descriptor

    override fun serialize(encoder: Encoder, value: TutorialDocComplexRight) {
        encoder.encodeSerializableValue(Surrogate.serializer(), Surrogate(value.value))
    }

    override fun deserialize(decoder: Decoder): TutorialDocComplexRight =
        TutorialDocComplexRight(decoder.decodeSerializableValue(Surrogate.serializer()).value)
}
// --8<-- [end:kxs-leading-tags-custom-ambiguous-definitions]

private fun customComplexWithoutTagsIsRejected() {
    // --8<-- [start:kxs-leading-tags-custom-ambiguous-roundtrip]
    val value = TutorialDocCustomComplexAmbiguous(
        left = TutorialDocComplexLeft(1),
        right = null,
    )
    shouldThrow<SerializationException> {
        DER.encodeToByteArray(value) /* (1)! */
    }
    // --8<-- [end:kxs-leading-tags-custom-ambiguous-roundtrip]
}

// --8<-- [start:kxs-leading-tags-custom-disambiguated-definitions]
@Serializable(with = TutorialDocScalarLeftSerializer::class)
private data class TutorialDocScalarLeft(val value: Int)

@Serializable(with = TutorialDocScalarRightSerializer::class)
private data class TutorialDocScalarRight(val value: String)

@Serializable
private data class TutorialDocCustomByLeadingTags(
    val left: TutorialDocScalarLeft?,
    val right: TutorialDocScalarRight?,
)

private object TutorialDocScalarLeftSerializer : KSerializer<TutorialDocScalarLeft> {
    private val baseDescriptor = PrimitiveSerialDescriptor("TutorialDocScalarLeft", PrimitiveKind.INT)
    override val descriptor: SerialDescriptor =
        baseDescriptor.withAsn1LeadingTags(setOf(Asn1Element.Tag.INT))

    override fun serialize(encoder: Encoder, value: TutorialDocScalarLeft) {
        encoder.encodeInt(value.value)
    }

    override fun deserialize(decoder: Decoder): TutorialDocScalarLeft =
        TutorialDocScalarLeft(decoder.decodeInt())
}

private object TutorialDocScalarRightSerializer : KSerializer<TutorialDocScalarRight> {
    private val baseDescriptor = PrimitiveSerialDescriptor("TutorialDocScalarRight", PrimitiveKind.STRING)
    override val descriptor: SerialDescriptor =
        baseDescriptor.withDynamicAsn1LeadingTags { setOf(Asn1Element.Tag.STRING_UTF8) }

    override fun serialize(encoder: Encoder, value: TutorialDocScalarRight) {
        encoder.encodeString(value.value)
    }

    override fun deserialize(decoder: Decoder): TutorialDocScalarRight =
        TutorialDocScalarRight(decoder.decodeString())
}
// --8<-- [end:kxs-leading-tags-custom-disambiguated-definitions]

private fun customLeadingTagsRoundTrip(): Pair<ByteArray, TutorialDocCustomByLeadingTags> {
    // --8<-- [start:kxs-leading-tags-custom-disambiguated-roundtrip]
    val value = TutorialDocCustomByLeadingTags(
        left = null,
        right = TutorialDocScalarRight("B")
    )
    val der = DER.encodeToByteArray(value)
    check(der.toHexString() == "30030c0142") /* (1)! */
    // --8<-- [end:kxs-leading-tags-custom-disambiguated-roundtrip]
    return der to DER.decodeFromByteArray(der)
}

// --8<-- [start:kxs-open-poly-tag-rfc-definitions]
private interface TutorialDocGeneralNameByTag

@Serializable
@Asn1Tag(
    tagNumber = 2u,
    tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
    constructed = Asn1ConstructedBit.PRIMITIVE,
)
@JvmInline
private value class TutorialDocGeneralNameDns(
    val value: String,
) : TutorialDocGeneralNameByTag

@Serializable
@Asn1Tag(
    tagNumber = 6u,
    tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
    constructed = Asn1ConstructedBit.PRIMITIVE,
)
@JvmInline
private value class TutorialDocGeneralNameUri(
    val value: String,
) : TutorialDocGeneralNameByTag
// --8<-- [end:kxs-open-poly-tag-rfc-definitions]

private fun openPolyByTagRfcLikeRoundTrip(value: TutorialDocGeneralNameByTag): Pair<ByteArray, TutorialDocGeneralNameByTag> {
    // --8<-- [start:kxs-open-poly-tag-rfc-roundtrip]
    val codec = DER {
        serializersModule = SerializersModule {
            polymorphicByTag(TutorialDocGeneralNameByTag::class, serialName = "TutorialDocGeneralNameByTag") {
                subtype<TutorialDocGeneralNameDns>()
                subtype<TutorialDocGeneralNameUri>()
            }
        }
    }
    val der = codec.encodeToByteArray(value)
    val derHex = der.toHexString()
    when (value) {
        is TutorialDocGeneralNameDns -> check(derHex == /* (1)! */"820b6578616d706c652e636f6d") { derHex }
        is TutorialDocGeneralNameUri -> check(derHex == /* (2)! */"861368747470733a2f2f6578616d706c652e636f6d") { derHex }
    }
    // --8<-- [end:kxs-open-poly-tag-rfc-roundtrip]
    return der to codec.decodeFromByteArray(der)
}

// --8<-- [start:kxs-open-poly-tag-valueclass-definitions]
private interface TutorialDocOpenByTagValueClass

@Serializable
@JvmInline
private value class TutorialDocOpenByTagInt(
    val value: Int,
) : TutorialDocOpenByTagValueClass

@Serializable
@JvmInline
private value class TutorialDocOpenByTagBool(
    val value: Boolean,
) : TutorialDocOpenByTagValueClass
// --8<-- [end:kxs-open-poly-tag-valueclass-definitions]

private fun openPolyByTagValueClassRoundTrip(value: TutorialDocOpenByTagValueClass): Pair<ByteArray, TutorialDocOpenByTagValueClass> {
    // --8<-- [start:kxs-open-poly-tag-valueclass-roundtrip]
    val codec = DER {
        serializersModule = SerializersModule {
            polymorphicByTag(TutorialDocOpenByTagValueClass::class, serialName = "TutorialDocOpenByTagValueClass") {
                subtype<TutorialDocOpenByTagInt>()
                subtype<TutorialDocOpenByTagBool>()
            }
        }
    }
    val der = codec.encodeToByteArray(value)
    val derHex = der.toHexString()
    when (value) {
        is TutorialDocOpenByTagInt -> check(derHex == "020109") /* (1)! */
        is TutorialDocOpenByTagBool -> check(derHex == "0101ff") /* (2)! */
    }
    // --8<-- [end:kxs-open-poly-tag-valueclass-roundtrip]
    return der to codec.decodeFromByteArray(der)
}

// --8<-- [start:kxs-open-poly-oid-definitions]
private interface TutorialDocOpenByOid : Identifiable

@Serializable
private data class TutorialDocOpenByOidInt(
    val value: Int,
) : TutorialDocOpenByOid, Identifiable by Companion {
    companion object : OidProvider<TutorialDocOpenByOidInt> {
        @OptIn(ExperimentalUuidApi::class)
        override val oid: ObjectIdentifier = ObjectIdentifier(Uuid.parse("4932c522-dfce-453a-8c92-d792c0e50147"))
    }
}
// --8<-- [end:kxs-open-poly-oid-definitions]

private fun openPolyByOidRoundTrip(value: TutorialDocOpenByOid): Pair<ByteArray, TutorialDocOpenByOid> {
    // --8<-- [start:kxs-open-poly-oid-roundtrip]
    val codec = DER {
        serializersModule = SerializersModule {
            polymorphicByOid(TutorialDocOpenByOid::class, serialName = "TutorialDocOpenByOid") {
                subtype<TutorialDocOpenByOidInt>(TutorialDocOpenByOidInt)
            }
        }
    }
    val der = codec.encodeToByteArray(value)
    check(der.toHexString() == /* (1)! */"30190614698192b2e2c8dbfcf294f58cc9b5f2ac87948247020109")
    // --8<-- [end:kxs-open-poly-oid-roundtrip]
    return der to codec.decodeFromByteArray(der)
}

// --8<-- [start:kxs-map-set-definitions]
@Serializable
private data class TutorialDocMapAndSet(
    val map: Map<Int, Int>,
    val set: Set<Int>,
)
// --8<-- [end:kxs-map-set-definitions]

private fun mapAndSetRoundTrip(): Pair<ByteArray, TutorialDocMapAndSet> {
    // --8<-- [start:kxs-map-set-roundtrip]
    val value = TutorialDocMapAndSet(
        map = mapOf(1 to 2),
        set = setOf(3),
    )
    val der = DER.encodeToByteArray(value)
    check(der.toHexString() == /* (1)! */"300d30060201010201023103020103")
    // --8<-- [end:kxs-map-set-roundtrip]
    return der to DER.decodeFromByteArray(der)
}

// --8<-- [start:kxs-asn1serializer-top-level-encodable-definitions]
private data class TutorialDocSemanticVersion(
    val major: Int,
    val minor: Int,
) : Asn1Encodable<Asn1Sequence> {
    override fun encodeToTlv(): Asn1Sequence = Asn1.Sequence {
        +Asn1.Int(major)
        +Asn1.Int(minor)
    }

    companion object : Asn1Decodable<Asn1Sequence, TutorialDocSemanticVersion> {
        override fun doDecode(src: Asn1Sequence): TutorialDocSemanticVersion =
            TutorialDocSemanticVersion(
                major = src.children[0].asPrimitive().decodeToInt(),
                minor = src.children[1].asPrimitive().decodeToInt(),
            )
    }
}
// --8<-- [end:kxs-asn1serializer-top-level-encodable-definitions]

private fun topLevelEncodableRoundTrip(): Pair<ByteArray, TutorialDocSemanticVersion> {
    // --8<-- [start:kxs-asn1serializer-top-level-encodable-roundtrip]
    val value = TutorialDocSemanticVersion(major = 1, minor = 42)
    val der = value.encodeToDer()
    check(der.toHexString() == "300602010102012a") /* (1)! */
    // --8<-- [end:kxs-asn1serializer-top-level-encodable-roundtrip]
    return der to TutorialDocSemanticVersion.decodeFromDer(der)
}

// --8<-- [start:kxs-asn1serializer-property-without-bridge-definitions]
@Serializable
private data class TutorialDocAsn1SerializerMissingCarrier(
    @kotlinx.serialization.Contextual
    val version: TutorialDocSemanticVersion,
)
// --8<-- [end:kxs-asn1serializer-property-without-bridge-definitions]

private fun propertyWithoutBridgeFails() {
    // --8<-- [start:kxs-asn1serializer-property-without-bridge-roundtrip]
    val value = TutorialDocAsn1SerializerMissingCarrier(
        version = TutorialDocSemanticVersion(major = 1, minor = 42)
    )
    val der = DER.encodeToByteArray(value)
    shouldThrow<SerializationException> {
        DER.decodeFromByteArray<TutorialDocAsn1SerializerMissingCarrier>(der)
    }
    // --8<-- [end:kxs-asn1serializer-property-without-bridge-roundtrip]
}

// --8<-- [start:kxs-asn1serializer-property-with-bridge-definitions]
private object TutorialDocSemanticVersionBridgeSerializer : Asn1Serializer<Asn1Sequence, TutorialDocSemanticVersion>(
    leadingTags = setOf(Asn1Element.Tag.SEQUENCE),
    TutorialDocSemanticVersion
)

@Serializable
private data class TutorialDocAsn1SerializerBridgeCarrier(
    @Serializable(with = TutorialDocSemanticVersionBridgeSerializer::class)
    val version: TutorialDocSemanticVersion,
)
// --8<-- [end:kxs-asn1serializer-property-with-bridge-definitions]

private fun propertyWithBridgeRoundTrip(): Pair<ByteArray, TutorialDocAsn1SerializerBridgeCarrier> {
    // --8<-- [start:kxs-asn1serializer-property-with-bridge-roundtrip]
    val value = TutorialDocAsn1SerializerBridgeCarrier(
        version = TutorialDocSemanticVersion(major = 1, minor = 42)
    )
    val der = DER.encodeToByteArray(value)
    check(der.toHexString() == "3008300602010102012a") /* (1)! */
    // --8<-- [end:kxs-asn1serializer-property-with-bridge-roundtrip]
    return der to DER.decodeFromByteArray(der)
}

// --8<-- [start:kxs-raw-set-preservation-definitions]
@Serializable
private data class TutorialDocThirdPartyAlgorithms private constructor(
    val rawAlgorithms: Asn1Set,
) {
    constructor(algorithms: Set<ObjectIdentifier>) : this(
        rawAlgorithms = DER.encodeToTlv(algorithms).asSet()
    )

    @kotlinx.serialization.Transient
    val algorithms: Set<ObjectIdentifier> = DER.decodeFromDer(rawAlgorithms.derEncoded)
}
// --8<-- [end:kxs-raw-set-preservation-definitions]

private fun rawSetPreservationRoundTrip(): Triple<ByteArray, ByteArray, TutorialDocThirdPartyAlgorithms> {
    // --8<-- [start:kxs-raw-set-preservation-roundtrip]
    val oidShort = ObjectIdentifier("1.2.3")
    val oidLong = ObjectIdentifier("1.2.840.113549.1.1.11")

    val canonical = DER.encodeToByteArray(
        TutorialDocThirdPartyAlgorithms(
            algorithms = setOf(oidLong, oidShort)
        )
    )
    val canonicalHex = canonical.toHexString()
    check(canonicalHex == /* (1)! */"3011310f06022a0306092a864886f70d01010b") { "canonicalHex=$canonicalHex" }

    //sorting is messed up
    val nonCanonical = "3011310f06092a864886f70d01010b06022a03".hexToByteArray()
    val decoded = DER.decodeFromByteArray<TutorialDocThirdPartyAlgorithms>(nonCanonical)
    check(decoded.algorithms == setOf(oidShort, oidLong))

    val reencoded = DER.encodeToByteArray(decoded)
    val reencodedHex = reencoded.toHexString()
    check(reencodedHex == /* (2)! */"3011310f06092a864886f70d01010b06022a03") { "reencodedHex=$reencodedHex" }
    // --8<-- [end:kxs-raw-set-preservation-roundtrip]
    return Triple(canonical, reencoded, decoded)
}

@OptIn(ExperimentalStdlibApi::class)
val SerializationDocumentationTutorialTest by testSuite(
    testConfig = DefaultConfiguration
) {
    "Baseline" {
        val (der, decoded) = baselineRoundTrip()
        decoded shouldBe TutorialDocPerson(name = "A", age = 5)
        emitAsn1JsSample("kxs-baseline", der)
    }

    "Tag override" {
        val (der, decoded) = tagOverrideRoundTrip()
        decoded shouldBe TutorialDocTaggedInt(value = 5)
        emitAsn1JsSample("kxs-tag-override", der)
    }

    "Explicit wrapper" {
        val (der, decoded) = explicitRoundTrip()
        decoded shouldBe TutorialDocExplicitCarrier(wrapped = ExplicitlyTagged(5))
        emitAsn1JsSample("kxs-explicit-wrapper", der)
    }

    "Choice via sealed polymorphism" {
        val (intDer, intDecoded) = choiceRoundTrip(TutorialDocChoiceInt(7))
        intDecoded shouldBe TutorialDocChoiceInt(7)
        emitAsn1JsSample("kxs-choice-int", intDer)

        val (boolDer, boolDecoded) = choiceRoundTrip(TutorialDocChoiceBool(true))
        boolDecoded shouldBe TutorialDocChoiceBool(true)
        emitAsn1JsSample("kxs-choice-bool", boolDer)
    }

    "Primitive CHOICE via sealed inline wrappers" {
        val (intDer, intDecoded) = primitiveChoiceRoundTrip(TutorialDocPrimitiveChoiceInt(7))
        intDecoded shouldBe TutorialDocPrimitiveChoiceInt(7)
        emitAsn1JsSample("kxs-choice-primitive-int", intDer)

        val (boolDer, boolDecoded) = primitiveChoiceRoundTrip(TutorialDocPrimitiveChoiceBool(true))
        boolDecoded shouldBe TutorialDocPrimitiveChoiceBool(true)
        emitAsn1JsSample("kxs-choice-primitive-bool", boolDer)

        val (textDer, textDecoded) = primitiveChoiceRoundTrip(TutorialDocPrimitiveChoiceText("A"))
        textDecoded shouldBe TutorialDocPrimitiveChoiceText("A")
        emitAsn1JsSample("kxs-choice-primitive-text", textDer)
    }

    "Format options" {
        val (explicitNullDer, explicitNullDecoded) = explicitNullsRoundTrip()
        explicitNullDecoded shouldBe TutorialDocNullableInt(value = null)
        emitAsn1JsSample("kxs-format-options-explicit-nulls", explicitNullDer)

        val (defaultsDer, defaultsDecoded) = encodeDefaultsRoundTrip()
        defaultsDecoded shouldBe TutorialDocDefaults()
        emitAsn1JsSample("kxs-format-options-encode-defaults", defaultsDer)
    }

    "Leading tags deep dive" {
        val (nonNullDer, nonNullDecoded) = nonNullableNamesRoundTrip()
        nonNullDecoded shouldBe TutorialDocThreeNames("A", "B", "C")
        emitAsn1JsSample("kxs-leading-tags-non-null", nonNullDer)

        val (explicitNullDer, explicitNullDecoded) = nullableNamesWithExplicitNullsRoundTrip()
        explicitNullDecoded shouldBe TutorialDocThreeNullableNames("A", null, "C")
        emitAsn1JsSample("kxs-leading-tags-explicit-nulls", explicitNullDer)

        nullableNamesWithOmittedNullsAreRejected()

        val (implicitTagDer, implicitTagDecoded) = nullableNamesWithImplicitTagsRoundTrip()
        implicitTagDecoded shouldBe TutorialDocTaggedNullableNames("A", null, "C")
        emitAsn1JsSample("kxs-leading-tags-implicit-tagging", implicitTagDer)

        customComplexWithoutTagsIsRejected()

        val (customLeadingTagsDer, customLeadingTagsDecoded) = customLeadingTagsRoundTrip()
        customLeadingTagsDecoded shouldBe TutorialDocCustomByLeadingTags(
            left = null,
            right = TutorialDocScalarRight("B")
        )
        emitAsn1JsSample("kxs-leading-tags-custom-disambiguated", customLeadingTagsDer)
    }

    "Open polymorphism by tag" {
        val (rfcDnsDer, rfcDnsDecoded) = openPolyByTagRfcLikeRoundTrip(
            TutorialDocGeneralNameDns("example.com")
        )
        rfcDnsDecoded shouldBe TutorialDocGeneralNameDns("example.com")
        emitAsn1JsSample("kxs-open-poly-tag-rfc-dns", rfcDnsDer)

        val (rfcUriDer, rfcUriDecoded) = openPolyByTagRfcLikeRoundTrip(
            TutorialDocGeneralNameUri("https://example.com")
        )
        rfcUriDecoded shouldBe TutorialDocGeneralNameUri("https://example.com")
        emitAsn1JsSample("kxs-open-poly-tag-rfc-uri", rfcUriDer)

        val (intDer, intDecoded) = openPolyByTagValueClassRoundTrip(TutorialDocOpenByTagInt(9))
        intDecoded shouldBe TutorialDocOpenByTagInt(9)
        emitAsn1JsSample("kxs-open-poly-tag-valueclass-int", intDer)

        val (boolDer, boolDecoded) = openPolyByTagValueClassRoundTrip(TutorialDocOpenByTagBool(true))
        boolDecoded shouldBe TutorialDocOpenByTagBool(true)
        emitAsn1JsSample("kxs-open-poly-tag-valueclass-bool", boolDer)
    }

    "Open polymorphism by OID" {
        val (der, decoded) = openPolyByOidRoundTrip(TutorialDocOpenByOidInt(9))
        decoded shouldBe TutorialDocOpenByOidInt(9)
        emitAsn1JsSample("kxs-open-poly-oid", der)
    }

    "Map and Set" {
        val (der, decoded) = mapAndSetRoundTrip()
        decoded shouldBe TutorialDocMapAndSet(
            map = mapOf(1 to 2),
            set = setOf(3),
        )
        emitAsn1JsSample("kxs-map-set", der)
    }

    "Asn1Serializer bridge composition" {
        val (topLevelDer, topLevelDecoded) = topLevelEncodableRoundTrip()
        topLevelDecoded shouldBe TutorialDocSemanticVersion(major = 1, minor = 42)
        emitAsn1JsSample("kxs-asn1serializer-top-level-encodable", topLevelDer)

        propertyWithoutBridgeFails()

        val (bridgeDer, bridgeDecoded) = propertyWithBridgeRoundTrip()
        bridgeDecoded shouldBe TutorialDocAsn1SerializerBridgeCarrier(
            version = TutorialDocSemanticVersion(major = 1, minor = 42)
        )
        emitAsn1JsSample("kxs-asn1serializer-property-with-bridge", bridgeDer)
    }

    "Raw ASN.1 SET preserves third-party ordering" {
        val (canonicalDer, nonCanonicalDer, decoded) = rawSetPreservationRoundTrip()
        decoded.algorithms shouldBe setOf(
            ObjectIdentifier("1.2.3"),
            ObjectIdentifier("1.2.840.113549.1.1.11")
        )
        emitAsn1JsSample("kxs-raw-set-preservation-canonical", canonicalDer)
        emitAsn1JsSample("kxs-raw-set-preservation-noncanonical", nonCanonicalDer)
    }
}
