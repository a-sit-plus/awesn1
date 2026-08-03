package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.Pkcs10CsrAttribute
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension
import at.asitplus.awesn1.serialization.DER
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.pkcs.Attribute
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.Extensions

val Pkcs10CsrAttributeTest by matrixSuite {
    "extension request DER agrees with Bouncy Castle" - {
        "single" {
            val extensionValue = byteArrayOf(0x05, 0x00)
            val actual = Pkcs10CsrAttribute.ExtensionRequest(
                listOf(X509CertificateExtension(ObjectIdentifier("1.2.3"), value = extensionValue))
            )
            val expected = Attribute(
                PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                DERSet(Extensions(Extension(ASN1ObjectIdentifier("1.2.3"), false, extensionValue))),
            )

            DER.encodeToByteArray(Pkcs10CsrAttribute.serializer(), actual) shouldBe expected.encoded
        }

        "multiple" {
            val actual = Pkcs10CsrAttribute.ExtensionRequest(
                listOf(
                    X509CertificateExtension(ObjectIdentifier("1.2.3"), value = byteArrayOf(0x05, 0x00)),
                    X509CertificateExtension(ObjectIdentifier("1.2.4"), critical = true, value = byteArrayOf(0x04, 0x00)),
                )
            )
            val expected = Attribute(
                PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                DERSet(
                    Extensions(
                        arrayOf(
                            Extension(ASN1ObjectIdentifier("1.2.3"), false, byteArrayOf(0x05, 0x00)),
                            Extension(ASN1ObjectIdentifier("1.2.4"), true, byteArrayOf(0x04, 0x00)),
                        )
                    )
                ),
            )

            DER.encodeToByteArray(Pkcs10CsrAttribute.serializer(), actual) shouldBe expected.encoded
        }
    }
}
