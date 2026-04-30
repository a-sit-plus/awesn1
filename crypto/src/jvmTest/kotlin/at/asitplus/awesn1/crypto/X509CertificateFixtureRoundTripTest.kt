package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.PemBlock
import at.asitplus.awesn1.catchingUnwrapped
import at.asitplus.awesn1.crypto.pki.X509Certificate
import at.asitplus.awesn1.decodeAllFromPem
import at.asitplus.awesn1.serialization.DER
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.shouldBe
import java.io.ByteArrayInputStream
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.extension
import kotlin.io.path.name
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.time.toJavaInstant

private const val FIXTURE_ROOT = "certificate-fixtures"

val X509CertificateFixtureRoundTripTest by testSuite {
    val fixtures = certificateFixtures()

    withData(nameFn = { it.name }, data = fixtures) { path ->
        when (path.extension) {
            "der" -> {
                val encoded = path.readBytes()
                val jvmCert =
                    catchingUnwrapped { certificateFactory.generateCertificate(ByteArrayInputStream(encoded)) }.getOrNull()
                val decoded = DER.decodeFromByteArray(X509Certificate.serializer(), encoded)
                jvmCert?.let { assertEquals(decoded, it as java.security.cert.X509Certificate) }
                DER.encodeToByteArray(X509Certificate.serializer(), decoded) shouldBe encoded

                decodeLegacyCertificateAsCurrent(encoded) shouldBe decoded
            }

            "pem" -> {
                val blocks = PemBlock.decodeAllFromPem(path.readText()).filter { it.label == "CERTIFICATE" }
                blocks.shouldNotBeEmpty().forEach { block ->
                    val decoded = DER.decodeFromByteArray(X509Certificate.serializer(), block.payload)
                    DER.encodeToByteArray(X509Certificate.serializer(), decoded) shouldBe block.payload
                    decodeLegacyCertificateAsCurrent(block.payload) shouldBe decoded
                }
            }
        }
    }
}

private fun certificateFixtures(): List<Path> {
    val root = object {}.javaClass.classLoader.getResource(FIXTURE_ROOT)
        ?.toURI()
        ?.let(Path::of)
        ?: error("Missing test resource directory: $FIXTURE_ROOT")

    return Files.walk(root).use { paths ->
        paths
            .filter(Files::isRegularFile)
            .filter { path -> path.name.startsWith("ok-") }
            .filter { path -> path.extension == "der" || path.extension == "pem" }
            .sorted()
            .toList()
    }
}

internal fun assertEquals(
    ownDecoded: X509Certificate,
    certificate: java.security.cert.X509Certificate
) {
    ownDecoded.tbsCertificate.version shouldBe certificate.version
    ownDecoded.signatureValue.rawBytes shouldBe certificate.signature
    ownDecoded.signatureAlgorithm.oid.toString() shouldBe certificate.sigAlgOID
    ownDecoded.tbsCertificate.serialNumber.toString() shouldBe certificate.serialNumber.toString()
    ownDecoded.tbsCertificate.validity.validFrom.instant.toJavaInstant() shouldBe certificate.notBefore.toInstant()
    ownDecoded.tbsCertificate.validity.validUntil.instant.toJavaInstant() shouldBe certificate.notAfter.toInstant()
}
