package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.matrixConfig
import de.infix.testBalloon.framework.core.invocation
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestFormatCompatibility by matrixSuite(
    matrixConfig { execution= ExecutionMode.Sequential }
) {
    "Basic ASN.1 scalar serializers support non-ASN.1 formats" {
        val asn1String = Asn1String.UTF8("foo")
        Json.decodeFromString(
            Asn1String.serializer(),
            Json.encodeToString(Asn1String.serializer(), asn1String)
        ) shouldBe asn1String

        val asn1Integer = Asn1Integer(42)
        Json.decodeFromString(
            Asn1Integer.serializer(),
            Json.encodeToString(Asn1Integer.serializer(), asn1Integer)
        ) shouldBe asn1Integer

        val asn1Real = Asn1Real(3.25)
        Json.decodeFromString(
            Asn1Real.serializer(),
            Json.encodeToString(Asn1Real.serializer(), asn1Real)
        ) shouldBe asn1Real

        val oid = ObjectIdentifier("1.2.840.113549")
        Json.decodeFromString(
            ObjectIdentifier.serializer(),
            Json.encodeToString(ObjectIdentifier.serializer(), oid)
        ) shouldBe oid
    }

    "Asn1Integer subtype serializers delegate to the integer serializer and validate sign" {
        val positive = Asn1Integer(42) as Asn1Integer.Positive
        val negative = Asn1Integer(-42) as Asn1Integer.Negative

        Json.encodeToString(Asn1Integer.Positive.serializer(), positive) shouldBe "\"42\""
        Json.decodeFromString(
            Asn1Integer.Positive.serializer(),
            Json.encodeToString(Asn1Integer.serializer(), positive)
        ) shouldBe positive

        Json.encodeToString(Asn1Integer.Negative.serializer(), negative) shouldBe "\"-42\""
        Json.decodeFromString(
            Asn1Integer.Negative.serializer(),
            Json.encodeToString(Asn1Integer.serializer(), negative)
        ) shouldBe negative

        shouldThrow<SerializationException> {
            Json.decodeFromString(Asn1Integer.Positive.serializer(), "\"-42\"")
        }
        shouldThrow<SerializationException> {
            Json.decodeFromString(Asn1Integer.Negative.serializer(), "\"42\"")
        }

        DER.decodeFromByteArray(
            Asn1Integer.Positive.serializer(),
            DER.encodeToByteArray(Asn1Integer.serializer(), positive)
        ) shouldBe positive
        DER.decodeFromByteArray(
            Asn1Integer.Negative.serializer(),
            DER.encodeToByteArray(Asn1Integer.serializer(), negative)
        ) shouldBe negative

        shouldThrow<SerializationException> {
            DER.decodeFromByteArray(
                Asn1Integer.Positive.serializer(),
                DER.encodeToByteArray(Asn1Integer.serializer(), negative)
            )
        }
        shouldThrow<SerializationException> {
            DER.decodeFromByteArray(
                Asn1Integer.Negative.serializer(),
                DER.encodeToByteArray(Asn1Integer.serializer(), positive)
            )
        }
    }

    "ASN.1 element tree serializers support JSON fallback and DER" {
        val primitive = Asn1Primitive(7uL, byteArrayOf(0x01, 0x02))
        val sequence = Asn1.Sequence { +primitive }
        val set = Asn1.Set {
            +Asn1Primitive(4uL, byteArrayOf(0x02))
            +Asn1Primitive(4uL, byteArrayOf(0x01))
        }
        val setOf = Asn1.SetOf {
            +Asn1Primitive(4uL, byteArrayOf(0x02))
            +Asn1Primitive(4uL, byteArrayOf(0x01))
        } as Asn1SetOf
        val tagged = Asn1.ExplicitlyTagged(0uL) { +primitive }
        val custom = Asn1CustomStructure(listOf(primitive), 99uL)
        val customSequenceTag = Asn1CustomStructure(listOf(primitive), Asn1Element.Tag.SEQUENCE.tagValue)
        val customSetTag = Asn1CustomStructure(listOf(primitive), Asn1Element.Tag.SET.tagValue)
        val customPrimitive = Asn1CustomStructure.asPrimitive(listOf(primitive), 100uL)
        val encapsulatingOctets = Asn1EncapsulatingOctetString(listOf(primitive))
        val primitiveOctets = Asn1OctetString(byteArrayOf(0x01, 0x02, 0x03))

        fun <T> roundTripJsonAndDer(serializer: KSerializer<T>, value: T) {
            Json.decodeFromString(
                serializer,
                Json.encodeToString(serializer, value)
            ) shouldBe value
            DER.decodeFromByteArray(
                serializer,
                DER.encodeToByteArray(serializer, value)
            ) shouldBe value
        }

        roundTripJsonAndDer(Asn1Element.serializer(), sequence)
        roundTripJsonAndDer(Asn1Structure.serializer(), customPrimitive)
        roundTripJsonAndDer(Asn1ExplicitlyTagged.serializer(), tagged)
        roundTripJsonAndDer(Asn1Sequence.serializer(), sequence)
        roundTripJsonAndDer(Asn1CustomStructure.serializer(), custom)
        roundTripJsonAndDer(Asn1CustomStructure.serializer(), customSequenceTag)
        roundTripJsonAndDer(Asn1CustomStructure.serializer(), customSetTag)
        roundTripJsonAndDer(Asn1CustomStructure.serializer(), customPrimitive)
        roundTripJsonAndDer(Asn1EncapsulatingOctetString.serializer(), encapsulatingOctets)
        roundTripJsonAndDer(Asn1OctetString.serializer(), primitiveOctets)
        roundTripJsonAndDer(Asn1Set.serializer(), set)
        roundTripJsonAndDer(Asn1SetOf.serializer(), setOf)
        roundTripJsonAndDer(Asn1Primitive.serializer(), primitive)
        roundTripJsonAndDer(Asn1OctetString.serializer(), primitiveOctets)

        Json.decodeFromString(
            Asn1Sequence.serializer(),
            Json.encodeToString(Asn1Element.serializer(), sequence)
        ) shouldBe sequence
        Json.decodeFromString(
            Asn1Structure.serializer(),
            Json.encodeToString(Asn1CustomStructure.serializer(), customPrimitive)
        ) shouldBe customPrimitive

        Json.decodeFromString(
            Asn1CustomStructure.serializer(),
            Json.encodeToString(Asn1CustomStructure.serializer(), customSequenceTag)
        )::class shouldBe Asn1CustomStructure::class
        DER.decodeFromByteArray(
            Asn1CustomStructure.serializer(),
            DER.encodeToByteArray(Asn1CustomStructure.serializer(), customSequenceTag)
        )::class shouldBe Asn1CustomStructure::class
        Json.decodeFromString(
            Asn1CustomStructure.serializer(),
            Json.encodeToString(Asn1CustomStructure.serializer(), customSetTag)
        )::class shouldBe Asn1CustomStructure::class
        DER.decodeFromByteArray(
            Asn1CustomStructure.serializer(),
            DER.encodeToByteArray(Asn1CustomStructure.serializer(), customSetTag)
        )::class shouldBe Asn1CustomStructure::class
    }

    "Asn1SetOf DER serializer decodes back to Asn1SetOf" {
        val setOf = Asn1.SetOf {
            +Asn1Primitive(4uL, byteArrayOf(0x02))
            +Asn1Primitive(4uL, byteArrayOf(0x01))
        } as Asn1SetOf

        val encoded = DER.encodeToByteArray(Asn1SetOf.serializer(), setOf)

        encoded.toHexString() shouldBe "3106040101040102"
        DER.decodeFromByteArray(Asn1SetOf.serializer(), encoded) shouldBe setOf
    }

}
