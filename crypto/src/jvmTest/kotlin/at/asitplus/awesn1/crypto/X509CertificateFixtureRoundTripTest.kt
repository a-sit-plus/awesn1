package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Null
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.InternalAwesn1Api
import at.asitplus.awesn1.PemBlock
import at.asitplus.awesn1.catchingUnwrapped
import at.asitplus.awesn1.crypto.pki.X509Certificate
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
        if(ok) "empty" {} else
        data( fixtures, nameFn = { it.name }, replay = if(!ok) Indexes(216L) else null) test { path ->

            fun parseAndAssert() {
                when (path.extension) {
                    "der" -> {
                        val encoded = path.readBytes()
                        val jvmCert =
                            catchingUnwrapped { certificateFactory.generateCertificate(ByteArrayInputStream(encoded)) }.getOrNull()
                        val decoded = DER.decodeFromByteArray(X509Certificate.serializer(), encoded)
                        jvmCert?.let { assertEquals(decoded, it as java.security.cert.X509Certificate) }
                        DER.encodeToByteArray(X509Certificate.serializer(), decoded) shouldBe encoded
                        assertRejectsTrailingBytes(encoded)
                        assertRejectsUnexpectedChildren(decoded)

                        decodeLegacyCertificateAsCurrent(encoded) shouldBe decoded
                    }

                    "pem" -> {
                        val blocks = PemBlock.decodeAllFromPem(path.readText()).filter { it.pemLabel == "CERTIFICATE" }
                        blocks.shouldNotBeEmpty().forEach { block ->
                            val decoded = DER.decodeFromByteArray(X509Certificate.serializer(), block.payload)
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
