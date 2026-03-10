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
            Buffer().apply { derExplicitNulls.encodeToSink(
                PrimitiveImplicitStringAmbiguous(null)
            , this) }.readByteArray()
        }
        shouldThrow<SerializationException> { derExplicitNulls.decodeFromSource<PrimitiveImplicitStringAmbiguous>(Buffer().apply { write("3000".hexToByteArray()) }) }

        shouldThrow<SerializationException> {
            Buffer().apply { derExplicitNulls.encodeToSink(
                PrimitiveImplicitFloatAmbiguous(null)
            , this) }.readByteArray()
        }
        shouldThrow<SerializationException> { derExplicitNulls.decodeFromSource<PrimitiveImplicitFloatAmbiguous>(Buffer().apply { write("3000".hexToByteArray()) }) }

        shouldThrow<SerializationException> {
            Buffer().apply { derExplicitNulls.encodeToSink(
                PrimitiveImplicitDoubleAmbiguous(null)
            , this) }.readByteArray()
        }
        shouldThrow<SerializationException> { derExplicitNulls.decodeFromSource<PrimitiveImplicitDoubleAmbiguous>(Buffer().apply { write("3000".hexToByteArray()) }) }

        shouldThrow<SerializationException> {
            Buffer().apply { derExplicitNulls.encodeToSink(
                PrimitiveImplicitOctetStringAmbiguous(null)
            , this) }.readByteArray()
        }
        shouldThrow<SerializationException> {
            derExplicitNulls.decodeFromSource<PrimitiveImplicitOctetStringAmbiguous>(Buffer().apply { write("3000".hexToByteArray()) })
        }
    }

    "Implicit+explicitNulls is accepted for non-empty-capable primitives" {
        val longNull = PrimitiveImplicitLongSafe(null)
        derExplicitNulls.decodeFromSource<PrimitiveImplicitLongSafe>(Buffer().apply { write(
            Buffer().apply { derExplicitNulls.encodeToSink(
                longNull
            , this) }.readByteArray()
        ) }) shouldBe longNull
        val longSet = PrimitiveImplicitLongSafe(7L)
        derExplicitNulls.decodeFromSource<PrimitiveImplicitLongSafe>(Buffer().apply { write(
            Buffer().apply { derExplicitNulls.encodeToSink(
                longSet
            , this) }.readByteArray()
        ) }) shouldBe longSet

        val intNull = PrimitiveImplicitIntSafe(null)
        derExplicitNulls.decodeFromSource<PrimitiveImplicitIntSafe>(Buffer().apply { write(
            Buffer().apply { derExplicitNulls.encodeToSink(
                intNull
            , this) }.readByteArray()
        ) }) shouldBe intNull
        val intSet = PrimitiveImplicitIntSafe(7)
        derExplicitNulls.decodeFromSource<PrimitiveImplicitIntSafe>(Buffer().apply { write(
            Buffer().apply { derExplicitNulls.encodeToSink(
                intSet
            , this) }.readByteArray()
        ) }) shouldBe intSet

        val shortNull = PrimitiveImplicitShortSafe(null)
        derExplicitNulls.decodeFromSource<PrimitiveImplicitShortSafe>(Buffer().apply { write(
            Buffer().apply { derExplicitNulls.encodeToSink(
                shortNull
            , this) }.readByteArray()
        ) }) shouldBe shortNull
        val shortSet = PrimitiveImplicitShortSafe(7)
        derExplicitNulls.decodeFromSource<PrimitiveImplicitShortSafe>(Buffer().apply { write(
            Buffer().apply { derExplicitNulls.encodeToSink(
                shortSet
            , this) }.readByteArray()
        ) }) shouldBe shortSet
    }

    "No implicit tags remain unambiguous for empty-capable primitives" {
        val stringNull = PrimitiveNoImplicitStringSafe(null)
        DER.decodeFromSource<PrimitiveNoImplicitStringSafe>(Buffer().apply { write(
            Buffer().apply { DER.encodeToSink(
                stringNull
            , this) }.readByteArray()
        ) }) shouldBe stringNull
        val stringEmpty = PrimitiveNoImplicitStringSafe("")
        DER.decodeFromSource<PrimitiveNoImplicitStringSafe>(Buffer().apply { write(
            Buffer().apply { DER.encodeToSink(
                stringEmpty
            , this) }.readByteArray()
        ) }) shouldBe stringEmpty

        val floatNull = PrimitiveNoImplicitFloatSafe(null)
        DER.decodeFromSource<PrimitiveNoImplicitFloatSafe>(Buffer().apply { write(
            Buffer().apply { DER.encodeToSink(
                floatNull
            , this) }.readByteArray()
        ) }) shouldBe floatNull
        val floatZero = PrimitiveNoImplicitFloatSafe(0f)
        DER.decodeFromSource<PrimitiveNoImplicitFloatSafe>(Buffer().apply { write(
            Buffer().apply { DER.encodeToSink(
                floatZero
            , this) }.readByteArray()
        ) }) shouldBe floatZero

        val doubleNull = PrimitiveNoImplicitDoubleSafe(null)
        DER.decodeFromSource<PrimitiveNoImplicitDoubleSafe>(Buffer().apply { write(
            Buffer().apply { DER.encodeToSink(
                doubleNull
            , this) }.readByteArray()
        ) }) shouldBe doubleNull
        val doubleZero = PrimitiveNoImplicitDoubleSafe(0.0)
        DER.decodeFromSource<PrimitiveNoImplicitDoubleSafe>(Buffer().apply { write(
            Buffer().apply { DER.encodeToSink(
                doubleZero
            , this) }.readByteArray()
        ) }) shouldBe doubleZero
    }

    "Explicit wrapper does not rescue an inner ambiguous primitive/null encoding" {
        shouldThrow<SerializationException> {
            Buffer().apply { derExplicitNulls.encodeToSink(
                PrimitiveImplicitThenExplicitStringSafe(
                    ExplicitlyTagged(PrimitiveInnerImplicitNullableString(null))
                )
            , this) }.readByteArray()
        }
        shouldThrow<SerializationException> {
            derExplicitNulls.decodeFromSource<PrimitiveImplicitThenExplicitStringSafe>(Buffer().apply { write("3000".hexToByteArray()) })
        }
    }

    "Octet wrapping without implicit tagging remains unambiguous" {
        val valueNull = PrimitiveOctetStringSafe(
            OctetStringEncapsulated(PrimitiveInnerPlainNullableString(null))
        )
        DER.decodeFromSource<PrimitiveOctetStringSafe>(Buffer().apply { write(
            Buffer().apply { DER.encodeToSink(
                valueNull
            , this) }.readByteArray()
        ) }) shouldBe valueNull

        val valueEmpty = PrimitiveOctetStringSafe(
            OctetStringEncapsulated(PrimitiveInnerPlainNullableString(""))
        )
        DER.decodeFromSource<PrimitiveOctetStringSafe>(Buffer().apply { write(
            Buffer().apply { DER.encodeToSink(
                valueEmpty
            , this) }.readByteArray()
        ) }) shouldBe valueEmpty

        val octetsNull = PrimitiveNoImplicitOctetStringSafe(null)
        val decodedOctetsNull = DER.decodeFromSource<PrimitiveNoImplicitOctetStringSafe>(Buffer().apply { write(
            Buffer().apply { DER.encodeToSink(
                octetsNull
            , this) }.readByteArray()
        ) })
        decodedOctetsNull.value shouldBe null

        val octetsEmpty = PrimitiveNoImplicitOctetStringSafe(byteArrayOf())
        val decodedOctetsEmpty = DER.decodeFromSource<PrimitiveNoImplicitOctetStringSafe>(Buffer().apply { write(
            Buffer().apply { DER.encodeToSink(
                octetsEmpty
            , this) }.readByteArray()
        ) })
        decodedOctetsEmpty.value?.toList() shouldBe octetsEmpty.value?.toList()
    }

    "Octet wrapping does not disambiguate if implicit remains innermost" {
        shouldThrow<SerializationException> {
            Buffer().apply { derExplicitNulls.encodeToSink(
                PrimitiveOctetThenImplicitStringAmbiguous(
                    OctetStringEncapsulated(PrimitiveInnerImplicitNullableString41(null))
                )
            , this) }.readByteArray()
        }
        shouldThrow<SerializationException> {
            derExplicitNulls.decodeFromSource<PrimitiveOctetThenImplicitStringAmbiguous>(Buffer().apply { write("3000".hexToByteArray()) })
        }
    }

    "Bit string with implicit+explicitNulls remains unambiguous" {
        val valueNull = PrimitiveImplicitBitStringSafe(null)
        val encodedNull = Buffer().apply { derExplicitNulls.encodeToSink(
            valueNull
        , this) }.readByteArray()
        val decodedNull = derExplicitNulls.decodeFromSource<PrimitiveImplicitBitStringSafe>(Buffer().apply { write(encodedNull) })
        decodedNull.value shouldBe null

        val valueSet = PrimitiveImplicitBitStringSafe(byteArrayOf(0x01, 0x02))
        val encodedSet = Buffer().apply { derExplicitNulls.encodeToSink(
            valueSet
        , this) }.readByteArray()
        val decodedSet = derExplicitNulls.decodeFromSource<PrimitiveImplicitBitStringSafe>(Buffer().apply { write(encodedSet) })
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
