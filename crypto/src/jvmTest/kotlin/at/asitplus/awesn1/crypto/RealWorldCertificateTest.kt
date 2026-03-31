package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.crypto.pki.GeneralNames.Companion.findSubjectAltNames
import at.asitplus.awesn1.crypto.pki.X509Certificate
import at.asitplus.awesn1.decodeFromPem
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.collections.shouldContainAll
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.extension
import kotlin.io.path.nameWithoutExtension
import kotlin.io.path.readText

val RealWorldCertificateTest by testSuite {
    val root = object{}.javaClass.classLoader.getResource("real-world-certs")?.toURI()?.let(Path::of)
        ?: throw IllegalStateException("Missing real-world-certs dir in resources")

    withData(nameFn = Path::nameWithoutExtension,
        Files.walk(root)
            .filter(Files::isRegularFile)
            .filter { it.extension == "pem" }
            .sorted()
            .toList()
    )
    { file ->
        val certPEM = file.readText()
        val tld = file.nameWithoutExtension
        val cert = X509Certificate.decodeFromPem(certPEM)
        cert.findSubjectAltNames()!!.dnsNames shouldContainAll listOf(tld, "*.$tld")
    }
}
