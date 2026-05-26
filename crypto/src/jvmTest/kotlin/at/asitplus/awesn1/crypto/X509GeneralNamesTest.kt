package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.PemBlock
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.X509Certificate
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension
import at.asitplus.awesn1.crypto.pki.GeneralNameImplicitTags
import at.asitplus.awesn1.crypto.pki.X509GeneralNames
import at.asitplus.awesn1.crypto.pki.X509GeneralNames.Companion.findIssuerAltNames
import at.asitplus.awesn1.crypto.pki.X509GeneralNames.Companion.findSubjectAltNames
import at.asitplus.awesn1.decodeAllFromPem
import at.asitplus.awesn1.serialization.DER
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import java.nio.file.Path
import kotlin.io.path.readText

val X509GeneralNamesTest by testSuite {

    "subjectAltName extension extraction and serialization round-trips" {
        val cert = decodeCertificateFixture("ok-ext-subject-altname2.pem")
        val subjectAltNames = cert.findSubjectAltNames()

        subjectAltNames shouldNotBe null
        subjectAltNames!!.assertExpectedFixtureNames()
        subjectAltNames.assertRoundTripsWithExtension(cert.extension("2.5.29.17"))
    }

    "issuerAltName extension extraction and serialization round-trips" {
        val cert = decodeCertificateFixture("ok-ext-issuer-altname.pem")
        val issuerAltNames = cert.findIssuerAltNames()

        issuerAltNames shouldNotBe null
        issuerAltNames!!.assertExpectedFixtureNames()
        issuerAltNames.assertRoundTripsWithExtension(cert.extension("2.5.29.18"))
    }

    "missing subjectAltName and issuerAltName extensions decode as null" {
        val cert = decodeCertificateFixture("ok-v1.pem")

        cert.findSubjectAltNames() shouldBe null
        cert.findIssuerAltNames() shouldBe null
    }
}

private fun decodeCertificateFixture(name: String): X509Certificate {
    val fixture = object {}.javaClass.classLoader
        .getResource("certificate-fixtures/certs/$name")
        ?.toURI()
        ?.let(Path::of)
        ?: error("Missing certificate fixture: $name")

    return PemBlock.decodeAllFromPem(fixture.readText())
        .first { it.label == X509Certificate.PEM_LABEL }
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
    val typeId = ObjectIdentifier.decodeFromAsn1ContentBytes(otherName.children[0].asPrimitive().content)
    val value = otherName.children[1]
        .also { it.tag shouldBe GeneralNameImplicitTags.otherName }
        .asStructure()
        .children
        .single()
        .asPrimitive()
        .content
        .decodeToString()

    typeId shouldBe ObjectIdentifier("1.2.3.4")
    value shouldBe "some other identifier"
}

private fun X509GeneralNames.assertRoundTripsWithExtension(extension: X509CertificateExtension) {
    val decoded = DER.decodeFromByteArray(X509GeneralNames.serializer(), extension.value)

    decoded.derEncodedEntries() shouldBe derEncodedEntries()
    DER.encodeToByteArray(X509GeneralNames.serializer(), this) shouldBe extension.value
}

private fun X509GeneralNames.derEncodedEntries(): List<List<Byte>> =
    entries.map { it.derEncoded.toList() }
