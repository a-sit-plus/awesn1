package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.pki.*
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.decodeFromTlv
import at.asitplus.awesn1.serialization.encodeToTlv
import at.asitplus.testballoon.matrix.CompactScope
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.json.Json
import kotlin.random.Random
import kotlin.time.Instant
import io.kotest.property.arbitrary.arbitrary as kotestArbitrary

val CryptoDerRoundTripTest by matrixSuite {
    "PKCS #10 request info equality and hash ignore attribute order" {
        val ordered = certificationRequestInfo(linkedSetOf(SMALLER_ATTRIBUTE, LARGER_ATTRIBUTE))
        val reversed = certificationRequestInfo(linkedSetOf(LARGER_ATTRIBUTE, SMALLER_ATTRIBUTE))

        ordered shouldBe reversed
        ordered.hashCode() shouldBe reversed.hashCode()
    }

    "programmatic PKCS #10 attributes are canonically sorted" {
        DER.decodeFromTlv<Pkcs10CertificationRequestInfo>(
            DER.encodeToTlv(
                certificationRequestInfo(
                    linkedSetOf(
                        LARGER_ATTRIBUTE,
                        SMALLER_ATTRIBUTE
                    )
                )
            )
        ).rawAttributes shouldBe listOf(SMALLER_ATTRIBUTE, LARGER_ATTRIBUTE)
    }

    "decoded PKCS #10 rawAttributes retain wire order" {
        val canonical = DER.encodeToTlv(
            certificationRequestInfo(linkedSetOf(SMALLER_ATTRIBUTE, LARGER_ATTRIBUTE))
        ).asSequence()
        val attributes = canonical.children.last().asStructure()
        val nonCanonical = Asn1.Sequence {
            canonical.children.dropLast(1).forEach { +it }
            +Asn1CustomStructure(attributes.children.reversed(), 0uL, TagClass.CONTEXT_SPECIFIC)
        }

        DER.decodeFromByteArray<Pkcs10CertificationRequestInfo>(nonCanonical.derEncoded).rawAttributes shouldBe
                listOf(LARGER_ATTRIBUTE, SMALLER_ATTRIBUTE)
    }

    "malformed PKCS #10 duplicate attributes decode into rawAttributes" {
        malformedCertificationRequestInfo().rawAttributes.map { it.oid } shouldBe listOf(
            DUPLICATE_ATTRIBUTE_OID, DUPLICATE_ATTRIBUTE_OID
        )
    }

    "PKCS #10 attributes rejects duplicate OIDs" {
        shouldThrow<Asn1Exception> { malformedCertificationRequestInfo().attributes }
    }

    "Property checks" - {
        compact("SignatureValue from raw bit string") - { checkRoundTrip(::randomRawBitStringSignatureValue) }
        compact("SignatureValue from raw bytes") - { checkRoundTrip(::randomBitStringSignatureValue) }
        compact("SignatureValue from ECDSA components") - { checkRoundTrip(::randomEcdsaSignatureValue) }
        compact("EcPrivateKeyInfo") - { checkRoundTrip(::randomEcPrivateKey) }
        compact("EncryptedPrivateKeyInfo") - { checkRoundTrip(::randomEncryptedPrivateKeyInfo) }
        compact("RsaOtherPrimeInfo") - { checkRoundTrip(::randomRsaOtherPrimeInfo) }
        compact("RsaPrivateKeyInfo") - { checkRoundTrip(::randomRsaPrivateKey) }
        compact("RsaPublicKeyInfo") - { checkRoundTrip(::randomRsaPublicKey) }
        compact("SignatureAlgorithmIdentifier") - { checkRoundTrip(::randomSignatureAlgorithmIdentifier) }
        compact("SubjectPublicKeyInfo") - { checkRoundTrip(::randomSubjectPublicKeyInfo) }
        compact("X509CertificateExtension") - { checkRoundTrip(::randomX509CertificateExtension) }
        compact("AttributeTypeAndValue") - { checkRoundTrip(::randomAttributeTypeAndValue) }
        compact("RelativeDistinguishedName") - { checkRoundTrip(::randomRelativeDistinguishedName) }
        compact("Attribute") - { checkRoundTrip(::randomAttribute) }
        compact("Pkcs8PrivateKeyInfo") - { checkRoundTrip(::randomPrivateKeyInfo) }
        compact("Pkcs10CertificationRequestInfo") - { checkRoundTrip(::randomPkcs10CertificationRequestInfo) }
        compact("Pkcs10CertificationRequest") - { checkRoundTrip(::randomPkcs10CertificationRequest) }
        compact("TbsCertificate") - { checkRoundTrip(::randomTbsCertificate) }
    }
}

private val SMALLER_ATTRIBUTE = Pkcs10CsrAttribute(ObjectIdentifier("1.2.3"), Asn1.Int(0))
private val LARGER_ATTRIBUTE = Pkcs10CsrAttribute(ObjectIdentifier("1.2.4"), Asn1.Int(0))
private val DUPLICATE_ATTRIBUTE_OID = ObjectIdentifier("1.2.3")

private fun certificationRequestInfo(attributes: Set<Pkcs10CsrAttribute>) = Pkcs10CertificationRequestInfo(
    subjectName = X500Name(emptyList()),
    publicKey = SubjectPublicKeyInfo.ec(ObjectIdentifier("1.2.3"), byteArrayOf(4)),
    attributes = attributes,
)

private fun malformedCertificationRequestInfo(): Pkcs10CertificationRequestInfo =
    DER.decodeFromByteArray(
        DER.encodeToByteArray(
            Pkcs10CertificationRequestInfo(
                subjectName = X500Name(emptyList()),
                publicKey = SubjectPublicKeyInfo.ec(ObjectIdentifier("1.2.3"), byteArrayOf(4)),
                attributes = setOf(
                    Pkcs10CsrAttribute(DUPLICATE_ATTRIBUTE_OID, Asn1.Int(0)),
                    Pkcs10CsrAttribute(DUPLICATE_ATTRIBUTE_OID, Asn1.Int(1)),
                ),
            )
        )
    )

private inline fun <reified T> CompactScope.checkRoundTrip(noinline generator: (Random) -> T) {
    property("value", kotestArbitrary { rs -> generator(rs.random) }) test { value ->
        val encoded = DER.encodeToByteArray<T>(value)
        DER.decodeFromByteArray<T>(encoded) shouldBe value
        if (value != null) {
            decodeLegacyAsCurrent(value as Any, encoded) shouldBe value
        }
    }
}

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
    2 -> Asn1OctetString(randomBytes(random))
    else -> Asn1BitString(randomBytes(random)).encodeToTlv()
}

private fun randomAlgorithmIdentifier(random: Random) = Asn1.Sequence {
    +randomOid(random)
    if (random.nextBoolean()) +Asn1.Null() else +randomRawElement(random)
}

private fun randomRawBitStringSignatureValue(random: Random) =
    X509SignatureValue(Asn1BitString(randomBytes(random)))

private fun randomBitStringSignatureValue(random: Random) =
    X509SignatureValue(randomBytes(random))

private fun randomEcdsaSignatureValue(random: Random) =
    EcdsaSigValue(positiveAsn1Integer(random), positiveAsn1Integer(random)).toX509SignatureValue()

private fun randomEcPrivateKey(random: Random) = Sec1EcPrivateKeyInfo(
    privateKey = randomBytes(random, 32),
    parameters = randomOid(random).takeIf { random.nextBoolean() },
    publicKey = Asn1BitString(randomBytes(random, 33)).takeIf { random.nextBoolean() },
)

private fun randomEncryptedPrivateKeyInfo(random: Random) = EncryptedPrivateKeyInfo(
    encryptionAlgorithm = X509AlgorithmIdentifier(
        oid = randomOid(random),
        parameters = randomRawElement(random).takeIf { random.nextBoolean() },
    ),
    encryptedData = if (random.nextBoolean()) Asn1EncapsulatingOctetString(
        listOf(Asn1OctetString(randomBytes(random, 32)))
    ) else Asn1OctetString(randomBytes(random, 32)),
).also { Json.decodeFromString<EncryptedPrivateKeyInfo>(Json.encodeToString(it)) }

private fun randomRsaOtherPrimeInfo(random: Random) = Pkcs1RsaOtherPrimeInfo(
    prime = positiveAsn1Integer(random),
    exponent = positiveAsn1Integer(random),
    coefficient = positiveAsn1Integer(random),
)

private fun randomRsaPrivateKey(random: Random) = Pkcs1RsaPrivateKeyInfo(
    version = if (random.nextBoolean()) Pkcs1RsaPrivateKeyInfo.Version.TWO_PRIME else Pkcs1RsaPrivateKeyInfo.Version.MULTI,
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

private fun randomRsaPublicKey(random: Random) = Pkcs1RsaPublicKeyInfo(
    modulus = positiveAsn1Integer(random),
    publicExponent = positiveAsn1Integer(random),
)

private fun randomSignatureAlgorithmIdentifier(random: Random) = X509AlgorithmIdentifier(
    oid = randomOid(random),
    parameters = randomRawElement(random),
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
        X509CertificateExtension(oid, critical, Asn1OctetString(randomBytes(random, 12)))
    } else {
        X509CertificateExtension(oid, critical, Asn1EncapsulatingOctetString(listOf(randomRawElement(random))))
    }
}

private fun randomAttributeTypeAndValue(random: Random): X500AttributeTypeAndValue {
    val stringValue = Asn1String.UTF8(randomAscii(random))
    return when (random.nextInt(5)) {
        0 -> X500AttributeTypeAndValue.CommonName(stringValue)
        1 -> X500AttributeTypeAndValue.Country(Asn1String.Printable("AT"))
        2 -> X500AttributeTypeAndValue.Organization(stringValue)
        3 -> X500AttributeTypeAndValue.OrganizationalUnit(stringValue)
        else -> X500AttributeTypeAndValue(randomOid(random), stringValue)
    }
}

private fun randomRelativeDistinguishedName(random: Random) =
    X500RelativeDistinguishedName(randomAttributeTypeAndValue(random))

private fun randomAttribute(random: Random) = Pkcs10CsrAttribute(randomOid(random), randomRawElement(random))

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
    subjectName = X500Name(List(random.nextInt(1, 3)) { randomRelativeDistinguishedName(random) }),
    publicKey = randomSubjectPublicKeyInfo(random),
    attributes = (List(random.nextInt(0, 3)) { randomAttribute(random) }).toSet(),
)

private fun randomPkcs10CertificationRequest(random: Random) = Pkcs10CertificationRequest(
    certificationRequestInfo = randomPkcs10CertificationRequestInfo(random),
    signatureAlgorithm = randomSignatureAlgorithmIdentifier(random),
    signatureValue = X509SignatureValue(randomBytes(random, 32)),
)

private fun randomTbsCertificate(random: Random): X509TbsCertificate {
    val validFrom = randomInstant(random)
    val validUntil = Instant.fromEpochSeconds(validFrom.epochSeconds + random.nextLong(1L, 86_400L * 90))
    return X509TbsCertificate(
        serialNumber = Asn1Integer.fromByteArray(randomBytes(random, 12), Asn1Integer.Sign.POSITIVE),
        signatureAlgorithm = randomSignatureAlgorithmIdentifier(random),
        issuerName = X500Name(List(random.nextInt(1, 3)) { randomRelativeDistinguishedName(random) }),
        validFrom = Asn1Time.SecondsCapped(validFrom),
        validUntil = Asn1Time.SecondsCapped(validUntil),
        subjectName = X500Name(List(random.nextInt(1, 3)) { randomRelativeDistinguishedName(random) }),
        subjectPublicKeyInfo = randomSubjectPublicKeyInfo(random),
        issuerUniqueID = Asn1BitString(randomBytes(random, 8)).takeIf { random.nextBoolean() },
        subjectUniqueID = Asn1BitString(randomBytes(random, 8)).takeIf { random.nextBoolean() },
        extensions = List(random.nextInt(0, 3)) { randomX509CertificateExtension(random) }.ifEmpty { null },
    )
}
