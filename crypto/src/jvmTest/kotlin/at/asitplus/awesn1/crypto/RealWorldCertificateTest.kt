package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.PemBlock
import at.asitplus.awesn1.crypto.pki.X509GeneralNames.Companion.findSubjectAltNames
import at.asitplus.awesn1.crypto.pki.X509Certificate
import at.asitplus.awesn1.decodeAllFromPem
import at.asitplus.awesn1.serialization.DER
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.collections.shouldContainAll
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
            .first { it.label == X509Certificate.PEM_LABEL }
            .payload
            .let { DER.decodeFromByteArray(X509Certificate.serializer(), it) }
        val jvmCert = certificateFactory.generateCertificate(
            ByteArrayInputStream(
            PemBlock.decodeAllFromPem(certPEM)
            .first { it.label == X509Certificate.PEM_LABEL }
            .payload))
        assertEquals(cert, jvmCert as java.security.cert.X509Certificate)
        cert.findSubjectAltNames()!!.dnsNames shouldContainAll listOf(tld, "*.$tld")
    }
}
