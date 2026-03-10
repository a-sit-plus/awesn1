package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.encoding.encodeToAsn1Primitive
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
val SerializationTestShapeContract by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "Nullable raw ASN.1 element in the middle is rejected as undecidable" {
        val value = AmbiguousMiddleNullableRawAsn1(
            prefix = 1, extension = null, suffix = 2
        )
        shouldThrow<SerializationException> {
            DER.encodeToByteArray(

                value
            )
        }
        shouldThrow<SerializationException> {
            DER.decodeFromByteArray<AmbiguousMiddleNullableRawAsn1>("3006020101020102".hexToByteArray())
        }
    }

    "Explicitly tagged nullable raw ASN.1 element in the middle is deterministic" {
        val withoutExtension = DisambiguatedMiddleNullableRawAsn1(
            prefix = 1, extension = null, suffix = 2
        )
        DER.decodeFromByteArray<DisambiguatedMiddleNullableRawAsn1>(
            DER.encodeToByteArray(
                withoutExtension
            )
        ) shouldBe withoutExtension

        val withExtension = DisambiguatedMiddleNullableRawAsn1(
            prefix = 1, extension = ExplicitlyTagged(99.encodeToAsn1Primitive()), suffix = 2
        )
        DER.decodeFromByteArray<DisambiguatedMiddleNullableRawAsn1>(
            DER.encodeToByteArray(
                withExtension
            )
        ) shouldBe withExtension
    }

    "Trailing nullable raw ASN.1 element remains supported" {
        val withoutExtension = TrailingNullableRawAsn1(
            prefix = 7, extension = null
        )
        DER.decodeFromByteArray<TrailingNullableRawAsn1>(
            DER.encodeToByteArray(
                withoutExtension
            )
        ) shouldBe withoutExtension

        val withExtension = TrailingNullableRawAsn1(
            prefix = 7, extension = 11.encodeToAsn1Primitive()
        )
        DER.decodeFromByteArray<TrailingNullableRawAsn1>(
            DER.encodeToByteArray(
                withExtension
            )
        ) shouldBe withExtension
    }
}

@Serializable
data class AmbiguousMiddleNullableRawAsn1(
    val prefix: Int,
    val extension: Asn1Element?,
    val suffix: Int,
)

@Serializable
data class DisambiguatedMiddleNullableRawAsn1(
    val prefix: Int,
    @Asn1Tag(
        tagNumber = 0u,
        constructed = Asn1ConstructedBit.CONSTRUCTED
    ) val extension: ExplicitlyTagged<Asn1Element>?,
    val suffix: Int,
)

@Serializable
data class TrailingNullableRawAsn1(
    val prefix: Int,
    val extension: Asn1Element?,
)
