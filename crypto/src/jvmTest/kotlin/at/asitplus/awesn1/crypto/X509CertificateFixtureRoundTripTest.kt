package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.decodeAllFromPem
import at.asitplus.awesn1.crypto.pki.X509Certificate
import at.asitplus.awesn1.encoding.decodeFromDer
import at.asitplus.awesn1.encoding.encodeToDer
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.extension
import kotlin.io.path.invariantSeparatorsPathString
import kotlin.io.path.name
import kotlin.io.path.readBytes
import kotlin.io.path.readText

private const val FIXTURE_ROOT = "certificate-fixtures"

val X509CertificateFixtureRoundTripTest by testSuite {
    val fixtures = certificateFixtures()

    withData(nameFn = { it.invariantSeparatorsPathString }, data = fixtures) { path ->
        when (path.extension) {
            "der" -> {
                val encoded = path.readBytes()
                X509Certificate.decodeFromDer(encoded).encodeToDer() shouldBe encoded
            }

            "pem" -> {
                val blocks = decodeAllFromPem(path.readText()).filter { it.label == "CERTIFICATE" }
                blocks.isNotEmpty() shouldBe true
                blocks.forEach { block ->
                    X509Certificate.decodeFromDer(block.payload).encodeToDer() shouldBe block.payload
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
