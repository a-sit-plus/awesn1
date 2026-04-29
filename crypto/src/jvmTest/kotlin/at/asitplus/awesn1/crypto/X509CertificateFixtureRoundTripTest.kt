package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.PemBlock
import at.asitplus.awesn1.decodeAllFromPem
import at.asitplus.awesn1.crypto.pki.X509Certificate
import at.asitplus.awesn1.serialization.DER
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.collections.shouldNotBeEmpty
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

    withData(nameFn = { it.name }, data = fixtures) { path ->
        when (path.extension) {
            "der" -> {
                val encoded = path.readBytes()
                val decoded = DER.decodeFromByteArray(X509Certificate.serializer(), encoded)
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
