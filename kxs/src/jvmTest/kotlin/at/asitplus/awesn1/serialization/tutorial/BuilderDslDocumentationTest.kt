// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)

package at.asitplus.awesn1.serialization

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
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.add
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.builtins.nullable
import kotlin.time.Instant

private fun sampleCertificate(serialNumber: Int) = X509Certificate(
    tbsCertificate = X509TbsCertificate(
        serialNumber = Asn1Integer(serialNumber),
        signatureAlgorithm = X509AlgorithmIdentifier(
            ObjectIdentifier("1.2.840.113549.1.1.11"),
            Asn1.Null(),
        ),
        issuerName = X500Name(X500RelativeDistinguishedName(X500AttributeTypeAndValue.CommonName("example"))),
        validFrom = SecondsCapped(Instant.fromEpochSeconds(1_700_000_000)),
        validUntil = SecondsCapped(Instant.fromEpochSeconds(1_800_000_000)),
        subjectName = X500Name(X500RelativeDistinguishedName(X500AttributeTypeAndValue.CommonName("example"))),
        subjectPublicKeyInfo = SubjectPublicKeyInfo.rsa(Pkcs1RsaPublicKeyInfo(Asn1Integer(3233), Asn1Integer(17))),
    ),
    signatureAlgorithm = X509AlgorithmIdentifier(
        ObjectIdentifier("1.2.840.113549.1.1.11"),
        Asn1.Null(),
    ),
    signatureValue = X509SignatureValue(byteArrayOf(1, 2, 3)),
)

val BuilderDslDocumentationTest by matrixSuite {
    "add encodes a serializable value with its inferred serializer" {
        val certificate = sampleCertificate(serialNumber = 1)
        val other = sampleCertificate(serialNumber = 2)
        // --8<-- [start:kxs-dsl-add-inferred]
        val envelope = with(DER) {
            Asn1.Sequence {
                add(certificate)
            }
        }
        // --8<-- [end:kxs-dsl-add-inferred]
        envelope.children shouldBe listOf(DER.encodeToTlv(certificate))
    }
    "add accepts an explicit serializer" {
        val certificate = sampleCertificate(serialNumber = 1)
        val other = sampleCertificate(serialNumber = 2)
        // --8<-- [start:kxs-dsl-add-explicit]
        val carrier = with(DER) {
            Asn1.Sequence {
                add(certificate)                              // inferred serializer
                add(X509Certificate.serializer(), other)      // explicit serializer
            }
        }
        // --8<-- [end:kxs-dsl-add-explicit]
        carrier.children shouldBe listOf(DER.encodeToTlv(certificate), DER.encodeToTlv(other))
    }
    "an omitted nullable appends nothing" {
        // --8<-- [start:kxs-dsl-add-nullable]
        val format = DER { explicitNulls = false }
        val envelope = with(format) {
            Asn1.Sequence {
                add(Int.serializer().nullable, null)
            }
        }
        // --8<-- [end:kxs-dsl-add-nullable]
        envelope.children shouldBe emptyList()
    }
    "transparent wrappers work with and without a Der context" {
        val algorithmIdentifier = X509AlgorithmIdentifier(ObjectIdentifier("1.2.840.113549.1.1.11"), Asn1.Null())
        val signatureValue = X509SignatureValue(byteArrayOf(1, 2, 3))
        // --8<-- [start:kxs-dsl-wrapper-forms]
        val withoutContext = Asn1.Sequence {
            add(algorithmIdentifier)
            add(signatureValue)
        }

        val withContext = with(DER) {
            Asn1.Sequence {
                add(algorithmIdentifier)
                add(signatureValue)
            }
        }
        // --8<-- [end:kxs-dsl-wrapper-forms]
        val expected = listOf(DER.encodeToTlv(algorithmIdentifier), DER.encodeToTlv(signatureValue))
        withoutContext.children shouldBe expected
        withContext.children shouldBe expected
    }
}
