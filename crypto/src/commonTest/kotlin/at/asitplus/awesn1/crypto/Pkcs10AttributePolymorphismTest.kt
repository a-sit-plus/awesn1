package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.Attribute
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequestInfo
import at.asitplus.awesn1.crypto.pki.RelativeDistinguishedName
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.serialization.DER
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

val Pkcs10AttributePolymorphismTest by testSuite {
    "Unknown PKCS#10 attribute stays raw by default" {
        val value = sampleRequestInfo(
            attributes = listOf(
                Attribute(
                    ObjectIdentifier("1.2.840.113549.1.9.7"),
                    Asn1String.UTF8("challenge").encodeToTlv()
                )
            )
        )

        val decoded = DER.decodeFromByteArray<Pkcs10CertificationRequestInfo>(DER.encodeToByteArray(value))
        decoded shouldBe value
        decoded.attributes.single()::class shouldBe Attribute::class
    }



    "Malformed extensionRequest payload fails clearly" {
        val malformed = Attribute(
            oid = ObjectIdentifier("1.2.840.113549.1.9.14"),
            values = setOf(
                Asn1.Sequence { },
                Asn1.Sequence { },
            ),
        )
        val value = sampleRequestInfo(attributes = listOf(malformed))

        shouldThrow<IllegalArgumentException> {
            val decodeFromByteArray =
                DER.decodeFromByteArray<Pkcs10CertificationRequestInfo>(DER.encodeToByteArray(value))
            decodeFromByteArray
        }.message shouldBe "At least one extension is required"
    }
}

private fun sampleRequestInfo(attributes: List<Attribute>) = Pkcs10CertificationRequestInfo(
    version = 0,
    subjectName = listOf(
        RelativeDistinguishedName(
            at.asitplus.awesn1.crypto.pki.AttributeTypeAndValue.CommonName(Asn1String.UTF8("example"))
        )
    ),
    publicKey = SubjectPublicKeyInfo.rsa(
        RsaPublicKeyInfo(
            Asn1Integer(17) as Asn1Integer.Positive,
            Asn1Integer(65537) as Asn1Integer.Positive,
        )
    ),
    attributes = attributes,
)