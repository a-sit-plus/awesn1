package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Null
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.InternalAwesn1Api
import at.asitplus.awesn1.PemBlock
import at.asitplus.awesn1.catchingUnwrapped
import at.asitplus.awesn1.crypto.pki.X509Certificate
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.awesn1.crypto.pki.X509GeneralNames
import at.asitplus.awesn1.crypto.pki.X509GeneralNames.Companion.findIssuerAltNames
import at.asitplus.awesn1.crypto.pki.X509GeneralNames.Companion.findSubjectAltNames
import at.asitplus.awesn1.decodeAllFromPem
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.decodeFromPem
import at.asitplus.awesn1.serialization.encodeToPem
import at.asitplus.awesn1.serialization.encodeToPemBlock
import at.asitplus.awesn1.serialization.encodeToTlv
import at.asitplus.testballoon.matrix.Indexes
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerializationException
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName as BouncyCastleGeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.OtherName
import org.bouncycastle.cert.X509CertificateHolder
import org.opentest4j.AssertionFailedError
import java.io.ByteArrayInputStream
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.extension
import kotlin.io.path.name
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.time.toJavaInstant

private const val FIXTURE_ROOT = "certificate-fixtures"

val X509CertificateFixtureRoundTripTest by matrixSuite {

    listOf(true, false).asData(name = "fixture kind", nameFn = { if (it) "OK only" else "Faulty only" }) - { ok ->
        val fixtures = certificateFixtures(ok)
        data(fixtures, nameFn = { it.name }, replay = if (!ok) Indexes(216L) else null) test { path ->

            fun parseAndAssert() {
                when (path.extension) {
                    "der" -> {
                        val encoded = path.readBytes()
                        val jvmCert =
                            catchingUnwrapped { certificateFactory.generateCertificate(ByteArrayInputStream(encoded)) }.getOrNull()
                        val decoded = DER.decodeFromByteArray(X509Certificate.serializer(), encoded)
                        jvmCert?.let { assertEquals(decoded, it as java.security.cert.X509Certificate) }
                        if (ok) assertGeneralNamesAgreeWithBouncyCastle(decoded, encoded)
                        DER.encodeToByteArray(X509Certificate.serializer(), decoded) shouldBe encoded
                        assertRejectsTrailingBytes(encoded)
                        assertRejectsUnexpectedChildren(decoded)

                        decodeLegacyCertificateAsCurrent(encoded) shouldBe decoded
                    }

                    "pem" -> {
                        val blocks = PemBlock.decodeAllFromPem(path.readText()).filter { it.pemLabel == "CERTIFICATE" }
                        blocks.shouldNotBeEmpty().forEach { block ->
                            val decoded = DER.decodeFromByteArray(X509Certificate.serializer(), block.payload)
                            if (ok) assertGeneralNamesAgreeWithBouncyCastle(decoded, block.payload)
                            val pemDecoded: X509Certificate = X509Certificate.decodeFromPem(block)
                            pemDecoded shouldBe decoded
                            pemDecoded.encodeToPemBlock() shouldBe block
                            pemDecoded.encodeToPem() shouldBe block.encodeToPem()
                            DER.encodeToByteArray(X509Certificate.serializer(), decoded) shouldBe block.payload
                            assertRejectsTrailingBytes(block.payload)
                            assertRejectsUnexpectedChildren(decoded)
                            decodeLegacyCertificateAsCurrent(block.payload) shouldBe decoded
                        }
                    }
                }
            }

            if (!ok) catchingUnwrapped {
                //we're more lenient than we should be, intentionally so
                parseAndAssert()
            }.onFailure {
                //here we re-encode s.t. it differs
                if ( path.name.contains("serial-negative")) it.shouldBeInstanceOf<AssertionFailedError>()
                //here we can't parse
                else it.shouldBeInstanceOf<SerializationException>()
            } else parseAndAssert()
        }
    }
}

private val structuralGeneralNamesDer = DER { }

internal fun assertGeneralNamesAgreeWithBouncyCastle(
    certificate: X509Certificate,
    encodedCertificate: ByteArray,
) {
    val bouncyCastle = X509CertificateHolder(encodedCertificate)
    assertGeneralNamesExtension(
        awesn1 = certificate.findSubjectAltNames(structuralGeneralNamesDer),
        bouncyCastle = bouncyCastle.getExtension(Extension.subjectAlternativeName),
    )
    assertGeneralNamesExtension(
        awesn1 = certificate.findIssuerAltNames(structuralGeneralNamesDer),
        bouncyCastle = bouncyCastle.getExtension(Extension.issuerAlternativeName),
    )
}

private fun assertGeneralNamesExtension(
    awesn1: X509GeneralNames?,
    bouncyCastle: Extension?,
) {
    (awesn1 == null) shouldBe (bouncyCastle == null)
    if (awesn1 == null || bouncyCastle == null) return

    val expected = GeneralNames.getInstance(bouncyCastle.parsedValue)
    structuralGeneralNamesDer.encodeToByteArray(X509GeneralNames.serializer(), awesn1) shouldBe expected.encoded
    awesn1.entries.size shouldBe expected.names.size

    awesn1.entries.zip(expected.names).forEach { (actual, reference) ->
        when (reference.tagNo) {
            BouncyCastleGeneralName.otherName -> {
                val actualOther = actual.shouldBeInstanceOf<X509GeneralName.Other>()
                    .value.shouldBeInstanceOf<X509GeneralName.Other.SemanticValue.Generic>()
                val referenceOther = OtherName.getInstance(reference.name)
                actualOther.oid.toString() shouldBe referenceOther.typeID.id
                actualOther.value.derEncoded shouldBe referenceOther.value.toASN1Primitive().encoded
            }
            BouncyCastleGeneralName.rfc822Name -> actual.shouldBeInstanceOf<X509GeneralName.Rfc822>()
            BouncyCastleGeneralName.dNSName -> actual.shouldBeInstanceOf<X509GeneralName.Dns>()
            BouncyCastleGeneralName.x400Address -> actual.shouldBeInstanceOf<X509GeneralName.X400Address>()
            BouncyCastleGeneralName.directoryName -> actual.shouldBeInstanceOf<X509GeneralName.Directory>()
            BouncyCastleGeneralName.ediPartyName -> actual.shouldBeInstanceOf<X509GeneralName.EdiParty>()
            BouncyCastleGeneralName.uniformResourceIdentifier ->
                actual.shouldBeInstanceOf<X509GeneralName.UniformResourceIdentifier>()
            BouncyCastleGeneralName.iPAddress -> actual.shouldBeInstanceOf<X509GeneralName.IpAddress>()
            BouncyCastleGeneralName.registeredID -> actual.shouldBeInstanceOf<X509GeneralName.RegisteredId>()
            else -> error("Bouncy Castle returned unknown GeneralName tag ${reference.tagNo}")
        }
    }
}

private fun assertRejectsTrailingBytes(encoded: ByteArray) {
    val trailingBytes = encoded + byteArrayOf(0x05, 0x00)

    shouldThrow<SerializationException> {
        DER.decodeFromByteArray(X509Certificate.serializer(), trailingBytes)
    }
    shouldThrow<SerializationException> {
        decodeLegacyCertificateAsCurrent(trailingBytes)
    }
}

@OptIn(ExperimentalSerializationApi::class, InternalAwesn1Api::class)
private fun assertRejectsUnexpectedChildren(decoded: X509Certificate) {
    val element = DER.encodeToTlv(decoded).asSequence()

    listOf(
        element.withBogusChild(),
        element.withBogusChildInTbsCertificate(),
        element.withBogusChildInValidity(),
    ).forEach { mutated ->
        shouldThrow<SerializationException> {
            DER.decodeFromByteArray(X509Certificate.serializer(), mutated.derEncoded)
        }
        shouldThrow<SerializationException> {
            decodeLegacyCertificateAsCurrent(mutated.derEncoded)
        }
    }
}

@OptIn(InternalAwesn1Api::class)
private fun Asn1Sequence.withBogusChild(): Asn1Sequence =
    Asn1Sequence(children + Asn1Null)

@OptIn(InternalAwesn1Api::class)
private fun Asn1Sequence.withBogusChildInTbsCertificate(): Asn1Sequence =
    copyWithChild(
        index = 0,
        child = children[0].asSequence().withBogusChild()
    )

@OptIn(InternalAwesn1Api::class)
private fun Asn1Sequence.withBogusChildInValidity(): Asn1Sequence {
    val tbsCertificate = children[0].asSequence()
    val validityIndex = tbsCertificate.children.indexOfFirst { child ->
        child is Asn1Sequence && child.children.size == 2 && child.children.all {
            it.tag == Asn1Element.Tag.TIME_UTC || it.tag == Asn1Element.Tag.TIME_GENERALIZED
        }
    }
    check(validityIndex >= 0) { "Could not locate certificate validity sequence" }

    return copyWithChild(
        index = 0,
        child = tbsCertificate.copyWithChild(
            index = validityIndex,
            child = tbsCertificate.children[validityIndex].asSequence().withBogusChild()
        )
    )
}

@OptIn(InternalAwesn1Api::class)
private fun Asn1Sequence.copyWithChild(index: Int, child: Asn1Element): Asn1Sequence =
    Asn1Sequence(children.toMutableList().also { it[index] = child })

private fun certificateFixtures(ok: Boolean): List<Path> {
    val root = object {}.javaClass.classLoader.getResource(FIXTURE_ROOT)
        ?.toURI()
        ?.let(Path::of)
        ?: error("Missing test resource directory: $FIXTURE_ROOT")

    return Files.walk(root).use { paths ->
        paths
            .filter(Files::isRegularFile)
            .filter { path -> path.name.startsWith("ok-") == ok }
            .filter { path -> path.extension == "der" || path.extension == "pem" }
            .sorted()
            .toList()
    }
}

internal fun assertEquals(
    ownDecoded: X509Certificate,
    certificate: java.security.cert.X509Certificate
) {
    ownDecoded.tbsCertificate.version.ordinal+1 shouldBe certificate.version
    ownDecoded.signatureValue.rawBytes shouldBe certificate.signature
    ownDecoded.signatureAlgorithm.oid.toString() shouldBe certificate.sigAlgOID
    ownDecoded.tbsCertificate.serialNumber.toString() shouldBe certificate.serialNumber.toString()
    ownDecoded.tbsCertificate.validity.validFrom.instant.toJavaInstant() shouldBe certificate.notBefore.toInstant()
    ownDecoded.tbsCertificate.validity.validUntil.instant.toJavaInstant() shouldBe certificate.notAfter.toInstant()
}
