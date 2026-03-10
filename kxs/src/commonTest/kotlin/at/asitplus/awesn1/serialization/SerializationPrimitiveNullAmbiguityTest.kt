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
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestPrimitiveNullAmbiguity by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    val derExplicitNulls = DER { explicitNulls = true }

    "Implicit+explicitNulls is rejected for empty-capable primitives" {
        shouldThrow<SerializationException> {
            derExplicitNulls.encodeToByteArray(
                PrimitiveImplicitStringAmbiguous(null)
            )
        }
        shouldThrow<SerializationException> { derExplicitNulls.decodeFromByteArray<PrimitiveImplicitStringAmbiguous>("3000".hexToByteArray()) }

        shouldThrow<SerializationException> {
            derExplicitNulls.encodeToByteArray(
                PrimitiveImplicitFloatAmbiguous(null)
            )
        }
        shouldThrow<SerializationException> { derExplicitNulls.decodeFromByteArray<PrimitiveImplicitFloatAmbiguous>("3000".hexToByteArray()) }

        shouldThrow<SerializationException> {
            derExplicitNulls.encodeToByteArray(
                PrimitiveImplicitDoubleAmbiguous(null)
            )
        }
        shouldThrow<SerializationException> { derExplicitNulls.decodeFromByteArray<PrimitiveImplicitDoubleAmbiguous>("3000".hexToByteArray()) }

        shouldThrow<SerializationException> {
            derExplicitNulls.encodeToByteArray(
                PrimitiveImplicitOctetStringAmbiguous(null)
            )
        }
        shouldThrow<SerializationException> {
            derExplicitNulls.decodeFromByteArray<PrimitiveImplicitOctetStringAmbiguous>("3000".hexToByteArray())
        }
    }

    "Implicit+explicitNulls is accepted for non-empty-capable primitives" {
        val longNull = PrimitiveImplicitLongSafe(null)
        derExplicitNulls.decodeFromByteArray<PrimitiveImplicitLongSafe>(
            derExplicitNulls.encodeToByteArray(
                longNull
            )
        ) shouldBe longNull
        val longSet = PrimitiveImplicitLongSafe(7L)
        derExplicitNulls.decodeFromByteArray<PrimitiveImplicitLongSafe>(
            derExplicitNulls.encodeToByteArray(
                longSet
            )
        ) shouldBe longSet

        val intNull = PrimitiveImplicitIntSafe(null)
        derExplicitNulls.decodeFromByteArray<PrimitiveImplicitIntSafe>(
            derExplicitNulls.encodeToByteArray(
                intNull
            )
        ) shouldBe intNull
        val intSet = PrimitiveImplicitIntSafe(7)
        derExplicitNulls.decodeFromByteArray<PrimitiveImplicitIntSafe>(
            derExplicitNulls.encodeToByteArray(
                intSet
            )
        ) shouldBe intSet

        val shortNull = PrimitiveImplicitShortSafe(null)
        derExplicitNulls.decodeFromByteArray<PrimitiveImplicitShortSafe>(
            derExplicitNulls.encodeToByteArray(
                shortNull
            )
        ) shouldBe shortNull
        val shortSet = PrimitiveImplicitShortSafe(7)
        derExplicitNulls.decodeFromByteArray<PrimitiveImplicitShortSafe>(
            derExplicitNulls.encodeToByteArray(
                shortSet
            )
        ) shouldBe shortSet
    }

    "No implicit tags remain unambiguous for empty-capable primitives" {
        val stringNull = PrimitiveNoImplicitStringSafe(null)
        DER.decodeFromByteArray<PrimitiveNoImplicitStringSafe>(
            DER.encodeToByteArray(
                stringNull
            )
        ) shouldBe stringNull
        val stringEmpty = PrimitiveNoImplicitStringSafe("")
        DER.decodeFromByteArray<PrimitiveNoImplicitStringSafe>(
            DER.encodeToByteArray(
                stringEmpty
            )
        ) shouldBe stringEmpty

        val floatNull = PrimitiveNoImplicitFloatSafe(null)
        DER.decodeFromByteArray<PrimitiveNoImplicitFloatSafe>(
            DER.encodeToByteArray(
                floatNull
            )
        ) shouldBe floatNull
        val floatZero = PrimitiveNoImplicitFloatSafe(0f)
        DER.decodeFromByteArray<PrimitiveNoImplicitFloatSafe>(
            DER.encodeToByteArray(
                floatZero
            )
        ) shouldBe floatZero

        val doubleNull = PrimitiveNoImplicitDoubleSafe(null)
        DER.decodeFromByteArray<PrimitiveNoImplicitDoubleSafe>(
            DER.encodeToByteArray(
                doubleNull
            )
        ) shouldBe doubleNull
        val doubleZero = PrimitiveNoImplicitDoubleSafe(0.0)
        DER.decodeFromByteArray<PrimitiveNoImplicitDoubleSafe>(
            DER.encodeToByteArray(
                doubleZero
            )
        ) shouldBe doubleZero
    }

    "Explicit wrapper does not rescue an inner ambiguous primitive/null encoding" {
        shouldThrow<SerializationException> {
            derExplicitNulls.encodeToByteArray(
                PrimitiveImplicitThenExplicitStringSafe(
                    ExplicitlyTagged(PrimitiveInnerImplicitNullableString(null))
                )
            )
        }
        shouldThrow<SerializationException> {
            derExplicitNulls.decodeFromByteArray<PrimitiveImplicitThenExplicitStringSafe>("3000".hexToByteArray())
        }
    }

    "Octet wrapping without implicit tagging remains unambiguous" {
        val valueNull = PrimitiveOctetStringSafe(
            OctetStringEncapsulated(PrimitiveInnerPlainNullableString(null))
        )
        DER.decodeFromByteArray<PrimitiveOctetStringSafe>(
            DER.encodeToByteArray(
                valueNull
            )
        ) shouldBe valueNull

        val valueEmpty = PrimitiveOctetStringSafe(
            OctetStringEncapsulated(PrimitiveInnerPlainNullableString(""))
        )
        DER.decodeFromByteArray<PrimitiveOctetStringSafe>(
            DER.encodeToByteArray(
                valueEmpty
            )
        ) shouldBe valueEmpty

        val octetsNull = PrimitiveNoImplicitOctetStringSafe(null)
        val decodedOctetsNull = DER.decodeFromByteArray<PrimitiveNoImplicitOctetStringSafe>(
            DER.encodeToByteArray(
                octetsNull
            )
        )
        decodedOctetsNull.value shouldBe null

        val octetsEmpty = PrimitiveNoImplicitOctetStringSafe(byteArrayOf())
        val decodedOctetsEmpty = DER.decodeFromByteArray<PrimitiveNoImplicitOctetStringSafe>(
            DER.encodeToByteArray(
                octetsEmpty
            )
        )
        decodedOctetsEmpty.value?.toList() shouldBe octetsEmpty.value?.toList()
    }

    "Octet wrapping does not disambiguate if implicit remains innermost" {
        shouldThrow<SerializationException> {
            derExplicitNulls.encodeToByteArray(
                PrimitiveOctetThenImplicitStringAmbiguous(
                    OctetStringEncapsulated(PrimitiveInnerImplicitNullableString41(null))
                )
            )
        }
        shouldThrow<SerializationException> {
            derExplicitNulls.decodeFromByteArray<PrimitiveOctetThenImplicitStringAmbiguous>("3000".hexToByteArray())
        }
    }

    "Bit string with implicit+explicitNulls remains unambiguous" {
        val valueNull = PrimitiveImplicitBitStringSafe(null)
        val encodedNull = derExplicitNulls.encodeToByteArray(
            valueNull
        )
        val decodedNull = derExplicitNulls.decodeFromByteArray<PrimitiveImplicitBitStringSafe>(encodedNull)
        decodedNull.value shouldBe null

        val valueSet = PrimitiveImplicitBitStringSafe(byteArrayOf(0x01, 0x02))
        val encodedSet = derExplicitNulls.encodeToByteArray(
            valueSet
        )
        val decodedSet = derExplicitNulls.decodeFromByteArray<PrimitiveImplicitBitStringSafe>(encodedSet)
        decodedSet.value?.toList() shouldBe valueSet.value?.toList()
    }
}

@Serializable
data class PrimitiveImplicitStringAmbiguous(
    @Asn1Tag(tagNumber = 10u) val value: String?
)

@Serializable
data class PrimitiveImplicitFloatAmbiguous(
    @Asn1Tag(tagNumber = 11u) val value: Float?
)

@Serializable
data class PrimitiveImplicitDoubleAmbiguous(
    @Asn1Tag(tagNumber = 12u) val value: Double?
)

@Serializable
data class PrimitiveImplicitOctetStringAmbiguous(
    @Asn1Tag(tagNumber = 13u) val value: ByteArray?
)

@Serializable
data class PrimitiveImplicitLongSafe(
    @Asn1Tag(tagNumber = 20u) val value: Long?
)

@Serializable
data class PrimitiveImplicitIntSafe(
    @Asn1Tag(tagNumber = 21u) val value: Int?
)

@Serializable
data class PrimitiveImplicitShortSafe(
    @Asn1Tag(tagNumber = 22u) val value: Short?
)

@Serializable
data class PrimitiveNoImplicitStringSafe(
    val value: String?
)

@Serializable
data class PrimitiveNoImplicitFloatSafe(
    val value: Float?
)

@Serializable
data class PrimitiveNoImplicitDoubleSafe(
    val value: Double?
)

@Serializable
data class PrimitiveImplicitThenExplicitStringSafe(
    @Asn1Tag(
        tagNumber = 31u,
        tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
        constructed = Asn1ConstructedBit.CONSTRUCTED,
    ) val value: ExplicitlyTagged<PrimitiveInnerImplicitNullableString>
)

@Serializable
data class PrimitiveInnerImplicitNullableString(
    @Asn1Tag(
        tagNumber = 30u,
        tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
    ) val value: String?
)

@Serializable
data class PrimitiveOctetStringSafe(
    val value: OctetStringEncapsulated<PrimitiveInnerPlainNullableString>
)

@Serializable
data class PrimitiveInnerPlainNullableString(
    val value: String?
)

@Serializable
data class PrimitiveNoImplicitOctetStringSafe(
    val value: ByteArray?
)

@Serializable
data class PrimitiveOctetThenImplicitStringAmbiguous(
    val value: OctetStringEncapsulated<PrimitiveInnerImplicitNullableString41>
)

@Serializable
data class PrimitiveInnerImplicitNullableString41(
    @Asn1Tag(
        tagNumber = 41u,
        tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
    ) val value: String?
)

@Serializable
data class PrimitiveImplicitBitStringSafe(
    @Asn1BitString @Asn1Tag(
        tagNumber = 50u,
        tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
    ) val value: ByteArray?
)
