package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.PemBlock
import at.asitplus.awesn1.crypto.pki.GeneralNames.Companion.findSubjectAltNames
import at.asitplus.awesn1.crypto.pki.X509Certificate
import at.asitplus.awesn1.decodeAllFromPem
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.decodeFromPem
import at.asitplus.awesn1.serialization.encodeToPem
import at.asitplus.awesn1.serialization.encodeToPemBlock
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.collections.shouldContainAll
import io.kotest.matchers.shouldBe
import java.io.ByteArrayInputStream
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.extension
import kotlin.io.path.nameWithoutExtension
import kotlin.io.path.readText

val RealWorldCertificateTest by testSuite {
    val root = object {}.javaClass.classLoader.getResource("real-world-certs")?.toURI()?.let(Path::of)
        ?: throw IllegalStateException("Missing real-world-certs dir in resources")

    withData(
        nameFn = Path::nameWithoutExtension,
        Files.walk(root)
            .filter(Files::isRegularFile)
            .filter { it.extension == "pem" }
            .sorted()
            .toList()
    )
    { file ->
        val certPEM = file.readText()
        val tld = file.nameWithoutExtension
        val cert = PemBlock.decodeAllFromPem(certPEM)
            .first { it.pemLabel == X509Certificate.canonicalPemLabel }
            .payload
            .let {
                DER.decodeFromByteArray(X509Certificate.serializer(), it)
            }
        val jvmCert = certificateFactory.generateCertificate(
            ByteArrayInputStream(
                PemBlock.decodeAllFromPem(certPEM)
                    .first { it.pemLabel == X509Certificate.canonicalPemLabel }.also {
                        val pemDecoded: X509Certificate = X509Certificate.decodeFromPem(it)
                        pemDecoded.encodeToPemBlock() shouldBe it
                        pemDecoded.encodeToPem() shouldBe it.encodeToPem()
                        pemDecoded shouldBe cert
                    }
                    .payload))
        assertEquals(cert, jvmCert as java.security.cert.X509Certificate)


        cert.findSubjectAltNames()!!.dnsNames shouldContainAll listOf(tld, "*.$tld")
    }
}
