package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1Real
import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json

val SerializationTestFormatCompatibility by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
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

}
