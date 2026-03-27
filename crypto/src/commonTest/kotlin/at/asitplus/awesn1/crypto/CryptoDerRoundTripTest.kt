package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1EncapsulatingOctetString
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1PrimitiveOctetString
import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.Asn1Time
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.Attribute
import at.asitplus.awesn1.crypto.pki.AttributeTypeAndValue
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequest
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequestInfo
import at.asitplus.awesn1.crypto.pki.RelativeDistinguishedName
import at.asitplus.awesn1.crypto.pki.TbsCertificate
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.serialization.DER
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlin.random.Random
import kotlin.time.Instant

private const val SAMPLE_COUNT = 5

val CryptoDerRoundTripTest by testSuite {
    withData(*sampleValues(::randomBitStringSignatureValue).toTypedArray()) {value ->
       roundTrip(value)
    }
    withData(*sampleValues(::randomEcdsaSignatureValue).toTypedArray()) {value ->
       roundTrip(value)
    }
    withData(*sampleValues(::randomEcPrivateKey).toTypedArray()) {value ->
       roundTrip(value)
    }
    withData(*sampleValues(::randomEncryptedPrivateKeyInfo).toTypedArray()) {value ->
       roundTrip(value)
    }
    withData(*sampleValues(::randomRsaOtherPrimeInfo).toTypedArray()) {value ->
       roundTrip(value)
    }
    withData(*sampleValues(::randomRsaPrivateKey).toTypedArray()) {value ->
       roundTrip(value)
    }
    withData(*sampleValues(::randomRsaPublicKey).toTypedArray()) {value ->
       roundTrip(value)
    }
    withData(*sampleValues(::randomSignatureAlgorithmIdentifier).toTypedArray()) {value ->
       roundTrip(value)
    }
    withData(*sampleValues(::randomSubjectPublicKeyInfo).toTypedArray()) {value ->
       roundTrip(value)
    }
    withData(*sampleValues(::randomX509CertificateExtension).toTypedArray()) {value ->
       roundTrip(value)
    }
    withData(*sampleValues(::randomAttributeTypeAndValue).toTypedArray()) {value ->
       roundTrip(value)
    }
    withData(*sampleValues(::randomRelativeDistinguishedName).toTypedArray()) {value ->
       roundTrip(value)
    }
    withData(*sampleValues(::randomAttribute).toTypedArray()) {value ->
       roundTrip(value)
    }
    withData(*sampleValues(::randomPrivateKeyInfo).toTypedArray()) {value ->
       roundTrip(value)
    }
    withData(*sampleValues(::randomPkcs10CertificationRequestInfo).toTypedArray()) {value ->
       roundTrip(value)
    }
    withData(*sampleValues(::randomPkcs10CertificationRequest).toTypedArray()) {value ->
       roundTrip(value)
    }
    withData(*sampleValues(::randomTbsCertificate).toTypedArray()) {value ->
       roundTrip(value)
    }
}

private inline fun <reified T> roundTrip(value: T) {
    DER.decodeFromByteArray<T>(DER.encodeToByteArray(value)) shouldBe value
}

private fun <T> sampleValues(generator: (Random) -> T): List<T> =
    List(SAMPLE_COUNT) { index -> generator(Random(0xA51u.toInt() + index)) }

private fun randomAscii(random: Random, length: Int = random.nextInt(3, 16)): String =
    buildString(length) {
        repeat(length) { append(('a'.code + random.nextInt(26)).toChar()) }
    }

private fun randomBytes(random: Random, size: Int = random.nextInt(1, 24)): ByteArray =
    ByteArray(size) { random.nextInt(0, 256).toByte() }

private fun randomOid(random: Random): ObjectIdentifier = ObjectIdentifier(
    "1.2.840.113549.${1 + random.nextInt(20)}.${1 + random.nextInt(20)}.${1 + random.nextInt(50)}"
)

private fun randomInstant(random: Random): Instant =
    Instant.fromEpochSeconds(1_700_000_000L + random.nextLong(0L, 1_000_000L))

private fun positiveAsn1Integer(random: Random): Asn1Integer.Positive =
    Asn1Integer(random.nextLong(1L, 10_000L)) as Asn1Integer.Positive

private fun randomRawElement(random: Random): Asn1Element = when (random.nextInt(4)) {
    0 -> Asn1Integer(random.nextLong(-10_000L, 10_000L)).encodeToTlv()
    1 -> Asn1String.UTF8(randomAscii(random)).encodeToTlv()
    2 -> Asn1PrimitiveOctetString(randomBytes(random))
    else -> Asn1BitString(randomBytes(random)).encodeToTlv()
}

private fun randomAlgorithmIdentifier(random: Random) = Asn1.Sequence {
    +randomOid(random)
    if (random.nextBoolean()) +Asn1.Null() else +randomRawElement(random)
}

private fun randomBitStringSignatureValue(random: Random) =
    (Asn1BitString(randomBytes(random)))

private fun randomEcdsaSignatureValue(random: Random) =
    SignatureValue(positiveAsn1Integer(random), positiveAsn1Integer(random))

private fun randomEcPrivateKey(random: Random) = EcPrivateKeyInfo(
    version = 1,
    privateKey = randomBytes(random, 32),
    parameters = randomOid(random).takeIf { random.nextBoolean() },
    publicKey = Asn1BitString(randomBytes(random, 33)).takeIf { random.nextBoolean() },
)

private fun randomEncryptedPrivateKeyInfo(random: Random) = EncryptedPrivateKeyInfo(
    encryptionAlgorithm = randomAlgorithmIdentifier(random),
    encryptedData = Asn1PrimitiveOctetString(randomBytes(random, 32)),
)

private fun randomRsaOtherPrimeInfo(random: Random) = RsaOtherPrimeInfo(
    prime = positiveAsn1Integer(random),
    exponent = positiveAsn1Integer(random),
    coefficient = positiveAsn1Integer(random),
)

private fun randomRsaPrivateKey(random: Random) = RsaPrivateKeyInfo(
    version = if (random.nextBoolean()) 0 else 1,
    modulus = positiveAsn1Integer(random),
    publicExponent = positiveAsn1Integer(random),
    privateExponent = positiveAsn1Integer(random),
    prime1 = positiveAsn1Integer(random),
    prime2 = positiveAsn1Integer(random),
    exponent1 = positiveAsn1Integer(random),
    exponent2 = positiveAsn1Integer(random),
    coefficient = positiveAsn1Integer(random),
    otherPrimeInfos = List(random.nextInt(0, 3)) { randomRsaOtherPrimeInfo(random) }.ifEmpty { null },
)

private fun randomRsaPublicKey(random: Random) = RsaPublicKeyInfo(
    modulus = positiveAsn1Integer(random),
    publicExponent = positiveAsn1Integer(random),
)

private fun randomSignatureAlgorithmIdentifier(random: Random) = SignatureAlgorithmIdentifier(
    oid = randomOid(random),
    parameters = List(random.nextInt(0, 3)) { randomRawElement(random) },
)

private fun randomSubjectPublicKeyInfo(random: Random): SubjectPublicKeyInfo =
    if (random.nextBoolean()) {
        SubjectPublicKeyInfo.rsa(randomRsaPublicKey(random))
    } else {
        SubjectPublicKeyInfo.ec(randomOid(random), randomBytes(random, 65))
    }

private fun randomX509CertificateExtension(random: Random): X509CertificateExtension {
    val oid = randomOid(random)
    val critical = random.nextBoolean()
    return if (random.nextBoolean()) {
        X509CertificateExtension(oid, critical, Asn1PrimitiveOctetString(randomBytes(random, 12)))
    } else {
        X509CertificateExtension(oid, critical, Asn1EncapsulatingOctetString(listOf(randomRawElement(random))))
    }
}

private fun randomAttributeTypeAndValue(random: Random): AttributeTypeAndValue {
    val stringValue = Asn1String.UTF8(randomAscii(random))
    return when (random.nextInt(5)) {
        0 -> AttributeTypeAndValue.CommonName(stringValue)
        1 -> AttributeTypeAndValue.Country(Asn1String.Printable("AT"))
        2 -> AttributeTypeAndValue.Organization(stringValue)
        3 -> AttributeTypeAndValue.OrganizationalUnit(stringValue)
        else -> AttributeTypeAndValue.Other(randomOid(random), stringValue)
    }
}

private fun randomRelativeDistinguishedName(random: Random) =
    RelativeDistinguishedName(randomAttributeTypeAndValue(random))

private fun randomAttribute(random: Random) = Attribute(randomOid(random), randomRawElement(random))

private fun randomPrivateKeyInfo(random: Random): Pkcs8PrivateKeyInfo =
    if (random.nextBoolean()) {
        Pkcs8PrivateKeyInfo.rsa(
            privateKey = randomRsaPrivateKey(random),
            attributes = null,
        )
    } else {
        Pkcs8PrivateKeyInfo.ec(
            sec1Key = randomEcPrivateKey(random),
            curveOid = randomOid(random),
            attributes = null,
        )
    }

private fun randomPkcs10CertificationRequestInfo(random: Random) = Pkcs10CertificationRequestInfo(
    version = 0,
    subjectName = List(random.nextInt(1, 3)) { randomRelativeDistinguishedName(random) },
    publicKey = randomSubjectPublicKeyInfo(random),
    attributes = List(random.nextInt(0, 3)) { randomAttribute(random) },
)

private fun randomPkcs10CertificationRequest(random: Random) = Pkcs10CertificationRequest(
    certificationRequestInfo = randomPkcs10CertificationRequestInfo(random),
    signatureAlgorithm = randomSignatureAlgorithmIdentifier(random),
    signatureValue = Asn1BitString(randomBytes(random, 32)),
)

private fun randomTbsCertificate(random: Random): TbsCertificate {
    val validFrom = randomInstant(random)
    val validUntil = Instant.fromEpochSeconds(validFrom.epochSeconds + random.nextLong(1L, 86_400L * 90))
    return TbsCertificate(
        version = 2,
        serialNumber = randomBytes(random, 12),
        signatureAlgorithm = randomSignatureAlgorithmIdentifier(random),
        issuerName = List(random.nextInt(1, 3)) { randomRelativeDistinguishedName(random) },
        validFrom = Asn1Time(validFrom),
        validUntil = Asn1Time(validUntil),
        subjectName = List(random.nextInt(1, 3)) { randomRelativeDistinguishedName(random) },
        subjectPublicKeyInfo = randomSubjectPublicKeyInfo(random),
        issuerUniqueID = Asn1BitString(randomBytes(random, 8)).takeIf { random.nextBoolean() },
        subjectUniqueID = Asn1BitString(randomBytes(random, 8)).takeIf { random.nextBoolean() },
        extensions = List(random.nextInt(0, 3)) { randomX509CertificateExtension(random) }.ifEmpty { null },
    )
}
