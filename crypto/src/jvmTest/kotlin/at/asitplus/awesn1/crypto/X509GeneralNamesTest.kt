package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.PemBlock
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.X509Certificate
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension
import at.asitplus.awesn1.crypto.pki.X509GeneralName.Tags
import at.asitplus.awesn1.crypto.pki.NameType
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.awesn1.crypto.pki.X500Name
import at.asitplus.awesn1.crypto.pki.X500RelativeDistinguishedName
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.awesn1.crypto.pki.X509GeneralNames
import at.asitplus.awesn1.crypto.pki.X509GeneralNames.Companion.findIssuerAltNames
import at.asitplus.awesn1.crypto.pki.X509GeneralNames.Companion.findSubjectAltNames
import at.asitplus.awesn1.decodeAllFromPem
import at.asitplus.awesn1.serialization.DER
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import java.nio.file.Path
import kotlin.io.path.readText

val X509GeneralNamesTest by matrixSuite {

    "subjectAltName extension extraction and serialization round-trips" {
        val cert = decodeCertificateFixture("ok-ext-subject-altname2.pem")
        val subjectAltNames = cert.findSubjectAltNames()

        subjectAltNames shouldNotBe null
        subjectAltNames!!.assertExpectedFixtureNames()
        subjectAltNames.assertShape()
        subjectAltNames.assertRoundTripsWithExtension(cert.extension("2.5.29.17"))
    }

    "issuerAltName extension extraction and serialization round-trips" {
        val cert = decodeCertificateFixture("ok-ext-issuer-altname.pem")
        val issuerAltNames = cert.findIssuerAltNames()

        issuerAltNames shouldNotBe null
        issuerAltNames!!.assertExpectedFixtureNames()
        issuerAltNames.assertShape()
        issuerAltNames.assertRoundTripsWithExtension(cert.extension("2.5.29.18"))
    }

    "missing subjectAltName and issuerAltName extensions decode as null" {
        val cert = decodeCertificateFixture("ok-v1.pem")

        cert.findSubjectAltNames() shouldBe null
        cert.findIssuerAltNames() shouldBe null
    }

    "malformed typed payload is preserved until accessed" {
        val encoded = at.asitplus.awesn1.encoding.Asn1.Sequence {
            +at.asitplus.awesn1.Asn1Primitive(X509GeneralName.Tags.dnsName, byteArrayOf(0xff.toByte()))
        }.derEncoded

        val decoded = DER.decodeFromByteArray(X509GeneralNames.serializer(), encoded)

        DER.encodeToByteArray(X509GeneralNames.serializer(), decoded) shouldBe encoded
        shouldThrow<Asn1Exception> { decoded.dnsNames }
    }

    "typed constructors encode and decode their CHOICE alternatives" {
        val opaqueSequence = at.asitplus.awesn1.encoding.Asn1.Sequence { }
        val names = X509GeneralNames(
            listOf(
                X509GeneralName.OtherName(ObjectIdentifier("1.2.3.4"), Asn1String.UTF8("other").encodeToTlv()),
                X509GeneralName.Rfc822Name("someone@example.com"),
                X509GeneralName.DnsName("example.com"),
                X509GeneralName.X400Address(opaqueSequence),
                X509GeneralName.DirectoryName(
                    X500Name(listOf(X500RelativeDistinguishedName(X500AttributeTypeAndValue.CommonName("subject"))))
                ),
                X509GeneralName.EdiPartyName(opaqueSequence),
                X509GeneralName.UniformResourceIdentifier("https://example.com"),
                X509GeneralName.IpAddress(byteArrayOf(127, 0, 0, 1)),
                X509GeneralName.RegisteredId(ObjectIdentifier("1.2.3.4")),
            )
        )

        val decoded = DER.decodeFromByteArray(
            X509GeneralNames.serializer(),
            DER.encodeToByteArray(X509GeneralNames.serializer(), names),
        )

        decoded shouldBe names
        decoded.entries.map { it.type } shouldBe NameType.entries
        decoded.dnsNames shouldBe listOf("example.com")
    }
}

private fun decodeCertificateFixture(name: String): X509Certificate {
    val fixture = object {}.javaClass.classLoader
        .getResource("certificate-fixtures/certs/$name")
        ?.toURI()
        ?.let(Path::of)
        ?: error("Missing certificate fixture: $name")

    return PemBlock.decodeAllFromPem(fixture.readText())
        .first { it.pemLabel == X509Certificate.PEM_LABEL }
        .payload
        .let { DER.decodeFromByteArray(X509Certificate.serializer(), it) }
}

private fun X509Certificate.extension(oid: String): X509CertificateExtension =
    tbsCertificate.extensions.orEmpty()
        .single { it.oid == ObjectIdentifier(oid) }

private fun X509GeneralNames.assertExpectedFixtureNames() {
    rfc822Names shouldBe listOf("someone@example.com")
    dnsNames shouldBe listOf("*.google.com")
    uris shouldBe listOf("http://example.com")
    ipAddresses.single().toList() shouldBe listOf(127, 0, 0, 1).map(Int::toByte)
    otherNames.size shouldBe 1
    assertOtherNameContent()
    directoryNames.size shouldBe 1
}

private fun X509GeneralNames.assertOtherNameContent() {
    val otherName = otherNames.single()
    val value = otherName.value
        .asPrimitive()
        .content
        .decodeToString()

    otherName.typeId shouldBe ObjectIdentifier("1.2.3.4")
    value shouldBe "some other identifier"
}

private fun X509GeneralNames.assertShape() {
    entries.single { it.asn1Representation.tag == Tags.otherName }
        .asn1Representation
        .asStructure()
        .children
        .let { children ->
            children.size shouldBe 2
            children[1].tag shouldBe Tags.otherNameValue
        }

    entries.single { it.asn1Representation.tag == Tags.rfc822Name }.asn1Representation.asPrimitive().tag shouldBe Tags.rfc822Name
    entries.single { it.asn1Representation.tag == Tags.dnsName }.asn1Representation.asPrimitive().tag shouldBe Tags.dnsName
    entries.single { it.asn1Representation.tag == Tags.uniformResourceIdentifier }.asn1Representation.asPrimitive().tag shouldBe Tags.uniformResourceIdentifier
    entries.single { it.asn1Representation.tag == Tags.ipAddress }.asn1Representation.asPrimitive().tag shouldBe Tags.ipAddress
    entries.single { it.asn1Representation.tag == Tags.registeredID }.asn1Representation.asPrimitive().tag shouldBe Tags.registeredID

    entries.single { it.asn1Representation.tag == Tags.directoryName }
        .asn1Representation
        .asStructure()
        .children
        .single()
        .tag shouldBe Asn1Element.Tag.SEQUENCE
}

private fun X509GeneralNames.assertRoundTripsWithExtension(extension: X509CertificateExtension) {
    val decoded = DER.decodeFromByteArray(X509GeneralNames.serializer(), extension.value)

    decoded.derEncodedEntries() shouldBe derEncodedEntries()
    DER.encodeToByteArray(X509GeneralNames.serializer(), this) shouldBe extension.value
}

private fun X509GeneralNames.derEncodedEntries(): List<List<Byte>> =
    entries.map { it.asn1Representation.derEncoded.toList() }
