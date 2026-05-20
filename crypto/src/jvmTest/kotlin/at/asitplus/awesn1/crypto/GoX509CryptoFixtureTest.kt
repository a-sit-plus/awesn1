package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.PemBlock
import at.asitplus.awesn1.crypto.legacy.RsaPrivateKeyInfo
import at.asitplus.awesn1.crypto.legacy.pki.Pkcs10CertificationRequestInfo
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequest
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequestInfo
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequestInfo.Version
import at.asitplus.awesn1.crypto.pki.X509TbsCertificate
import at.asitplus.awesn1.decodeFromPem
import at.asitplus.awesn1.serialization.DER
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.KSerializer
import java.nio.file.Path
import kotlin.io.path.readText

private const val GO_X509_FIXTURE_ROOT = "crypto-fixtures/go-x509"

val GoX509CryptoFixtureTest by testSuite {
    "PKCS#1 RSA private key" {
        val encoded = pemPayload("pkcs1-rsa-private-key.pem")
        val decoded = checkRoundTrip(encoded, Pkcs1RsaPrivateKeyInfo.serializer())

        decoded.version.ordinal shouldBe 0
        decoded.publicExponent.toString().toLong() shouldBe 65537L
    }

    "PKCS#1 RSA public key" {
        val encoded = hexFixture("pkcs1-rsa-public-key.hex")
        val decoded = checkRoundTrip(encoded, Pkcs1RsaPublicKeyInfo.serializer())

        decoded.publicExponent.toString().toLong() shouldBe 3L
    }

    withData(
        nameFn = { it.name },
        data = listOf(
            PublicKeyFixture("pkix-rsa-public-key.pem", rsa = true),
            PublicKeyFixture("pkix-ed25519-public-key.pem", rsa = false),
        ),
    ) { fixture ->
        val decoded = checkRoundTrip(
            pemPayload(fixture.name),
            SubjectPublicKeyInfo.serializer(),
        )

        if (fixture.rsa) {
            decoded.decodeRsaPublicKey().publicExponent.toString().toLong() shouldBe 65537L
        }
    }

    withData(
        nameFn = { it.name },
        data = listOf(
            PrivateKeyFixture("pkcs8-rsa-private-key.hex", NestedPrivateKey.RSA),
            PrivateKeyFixture("pkcs8-p256-private-key.hex", NestedPrivateKey.EC),
            PrivateKeyFixture("pkcs8-ed25519-private-key.hex", NestedPrivateKey.NONE),
        ),
    ) { fixture ->
        val decoded = checkRoundTrip(
            hexFixture(fixture.name),
            Pkcs8PrivateKeyInfo.serializer(),
        )

        when (fixture.nested) {
            NestedPrivateKey.RSA -> decoded.decodeRsaPrivateKey().version shouldBe Pkcs1RsaPrivateKeyInfo.Version.TWO_PRIME
            NestedPrivateKey.EC -> decoded.decodeEcPrivateKey().version shouldBe Sec1EcPrivateKeyInfo.Version.V1
            NestedPrivateKey.NONE -> Unit
        }
    }

    withData(
        nameFn = { it },
        data = listOf(
            "duplicate-attributes.csr.pem",
            "duplicate-extensions.csr.pem",
        ),
    ) { name ->
        val decoded = checkRoundTrip(
            pemPayload(name),
            Pkcs10CertificationRequest.serializer(),
        )

        decoded.certificationRequestInfo.version shouldBe  Pkcs10CertificationRequestInfo.Version.V1
    }
}

private data class PublicKeyFixture(val name: String, val rsa: Boolean)

private data class PrivateKeyFixture(val name: String, val nested: NestedPrivateKey)

private enum class NestedPrivateKey { RSA, EC, NONE }

private fun fixturePath(name: String): Path =
    object {}.javaClass.classLoader.getResource("$GO_X509_FIXTURE_ROOT/$name")
        ?.toURI()
        ?.let(Path::of)
        ?: error("Missing test fixture: $GO_X509_FIXTURE_ROOT/$name")

private fun pemPayload(name: String): ByteArray =
    PemBlock.decodeFromPem(fixturePath(name).readText()).payload

private fun hexFixture(name: String): ByteArray = fixturePath(name).readText()
    .filterNot(Char::isWhitespace).hexToByteArray()

private fun <T : Any> checkRoundTrip(encoded: ByteArray, serializer: KSerializer<T>): T {
    val decoded = DER.decodeFromByteArray(serializer, encoded)

    DER.encodeToByteArray(serializer, decoded) shouldBe encoded
    decodeLegacyAsCurrent(decoded, encoded) shouldBe decoded

    return decoded
}
