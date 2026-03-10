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

}
