package at.asitplus.awesn1.encoding

import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1Time.SecondsCapped
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.Pkcs1RsaPublicKeyInfo
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.crypto.X509SignatureValue
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.awesn1.crypto.pki.X500Name
import at.asitplus.awesn1.crypto.pki.X500RelativeDistinguishedName
import at.asitplus.awesn1.crypto.pki.X509Certificate
import at.asitplus.awesn1.crypto.pki.X509TbsCertificate
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.encodeToTlv
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.ExperimentalSerializationApi
import kotlin.time.Instant

@OptIn(ExperimentalSerializationApi::class)
val SerializationTreeBuilderTest by matrixSuite {
    "X509AlgorithmIdentifier unary plus works with and without DER context" {
        val algorithm = X509AlgorithmIdentifier(
            ObjectIdentifier("1.2.840.113549.1.1.11"),
            Asn1.Null(),
        )
        val expected = listOf(DER.encodeToTlv(algorithm))

        Asn1.Sequence { +algorithm }.children shouldBe expected
        with(DER) { Asn1.Sequence { +algorithm } }.children shouldBe expected
    }

    "X509SignatureValue unary plus works with and without DER context" {
        val signature = X509SignatureValue(byteArrayOf(1, 2, 3))
        val expected = listOf(DER.encodeToTlv(signature))

        Asn1.Sequence { +signature }.children shouldBe expected
        with(DER) { Asn1.Sequence { +signature } }.children shouldBe expected
    }

    "unary plus infers serializers for crypto types" {
        val publicKey = Pkcs1RsaPublicKeyInfo(Asn1Integer(3233), Asn1Integer(17))
        val algorithm = X509AlgorithmIdentifier(
            ObjectIdentifier("1.2.840.113549.1.1.11"),
            Asn1.Null(),
        )
        val name = X500Name(X500RelativeDistinguishedName(X500AttributeTypeAndValue.CommonName("example")))
        val certificate = X509Certificate(
            tbsCertificate = X509TbsCertificate(
                serialNumber = Asn1Integer(1),
                signatureAlgorithm = algorithm,
                issuerName = name,
                validFrom = SecondsCapped(Instant.fromEpochSeconds(1_700_000_000)),
                validUntil = SecondsCapped(Instant.fromEpochSeconds(1_800_000_000)),
                subjectName = name,
                subjectPublicKeyInfo = SubjectPublicKeyInfo.rsa(publicKey),
            ),
            signatureAlgorithm = algorithm,
            signatureValue = X509SignatureValue(byteArrayOf(1, 2, 3)),
        )

        with(DER) {
            Asn1.Sequence {
                +publicKey
                +certificate
            }
        }.children shouldBe listOf(
            DER.encodeToTlv(publicKey),
            DER.encodeToTlv(certificate),
        )
    }
}
