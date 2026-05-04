package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.crypto.legacy.EcPrivateKeyInfo as LegacyEcPrivateKeyInfo
import at.asitplus.awesn1.crypto.legacy.EncryptedPrivateKeyInfo as LegacyEncryptedPrivateKeyInfo
import at.asitplus.awesn1.crypto.legacy.Pkcs8PrivateKeyInfo as LegacyPkcs8PrivateKeyInfo
import at.asitplus.awesn1.crypto.legacy.RsaOtherPrimeInfo as LegacyRsaOtherPrimeInfo
import at.asitplus.awesn1.crypto.legacy.RsaPrivateKeyInfo as LegacyRsaPrivateKeyInfo
import at.asitplus.awesn1.crypto.legacy.RsaPublicKeyInfo as LegacyRsaPublicKeyInfo
import at.asitplus.awesn1.crypto.legacy.SignatureAlgorithmIdentifier as LegacySignatureAlgorithmIdentifier
import at.asitplus.awesn1.crypto.legacy.SignatureValue as LegacySignatureValue
import at.asitplus.awesn1.crypto.legacy.SubjectPublicKeyInfo as LegacySubjectPublicKeyInfo
import at.asitplus.awesn1.crypto.legacy.pki.Attribute as LegacyAttribute
import at.asitplus.awesn1.crypto.legacy.pki.AttributeTypeAndValue as LegacyAttributeTypeAndValue
import at.asitplus.awesn1.crypto.legacy.pki.Pkcs10CertificationRequest as LegacyPkcs10CertificationRequest
import at.asitplus.awesn1.crypto.legacy.pki.Pkcs10CertificationRequestInfo as LegacyPkcs10CertificationRequestInfo
import at.asitplus.awesn1.crypto.legacy.pki.RelativeDistinguishedName as LegacyRelativeDistinguishedName
import at.asitplus.awesn1.crypto.legacy.pki.TbsCertificate as LegacyTbsCertificate
import at.asitplus.awesn1.crypto.legacy.pki.X509Certificate as LegacyX509Certificate
import at.asitplus.awesn1.crypto.legacy.pki.X509CertificateExtension as LegacyX509CertificateExtension
import at.asitplus.awesn1.crypto.pki.Attribute
import at.asitplus.awesn1.crypto.pki.AttributeTypeAndValue
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequest
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequestInfo
import at.asitplus.awesn1.crypto.pki.X500RelativeDistinguishedName
import at.asitplus.awesn1.crypto.pki.TbsCertificate
import at.asitplus.awesn1.crypto.pki.X509Certificate
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension
import at.asitplus.awesn1.serialization.ExplicitlyTagged

internal fun decodeLegacyAsCurrent(value: Any, encoded: ByteArray): Any {
    val element = Asn1Element.parse(encoded)
    return when (value) {
        is EcPrivateKeyInfo -> LegacyEcPrivateKeyInfo.decodeFromTlv(element.asSequence()).toCurrent()
        is EncryptedPrivateKeyInfo -> LegacyEncryptedPrivateKeyInfo.decodeFromTlv(element.asSequence()).toCurrent()
        is Pkcs8PrivateKeyInfo -> LegacyPkcs8PrivateKeyInfo.decodeFromTlv(element.asSequence()).toCurrent()
        is RsaOtherPrimeInfo -> LegacyRsaOtherPrimeInfo.decodeFromTlv(element.asSequence()).toCurrent()
        is RsaPrivateKeyInfo -> LegacyRsaPrivateKeyInfo.decodeFromTlv(element.asSequence()).toCurrent()
        is RsaPublicKeyInfo -> LegacyRsaPublicKeyInfo.decodeFromTlv(element.asSequence()).toCurrent()
        is AlgorithmIdentifier -> LegacySignatureAlgorithmIdentifier.decodeFromTlv(element.asSequence()).toCurrent()
        is SignatureValue -> LegacySignatureValue.decodeFromTlv(element.asPrimitive()).toCurrent()
        is SubjectPublicKeyInfo -> LegacySubjectPublicKeyInfo.decodeFromTlv(element.asSequence()).toCurrent()
        is Attribute -> LegacyAttribute.decodeFromTlv(element.asSequence()).toCurrent()
        is AttributeTypeAndValue -> LegacyAttributeTypeAndValue.decodeFromTlv(element.asSequence()).toCurrent()
        is Pkcs10CertificationRequest -> LegacyPkcs10CertificationRequest.decodeFromTlv(element.asSequence()).toCurrent()
        is Pkcs10CertificationRequestInfo -> LegacyPkcs10CertificationRequestInfo.decodeFromTlv(element.asSequence()).toCurrent()
        is X500RelativeDistinguishedName -> LegacyRelativeDistinguishedName.decodeFromTlv(element.asSet()).toCurrent()
        is TbsCertificate -> LegacyTbsCertificate.decodeFromTlv(element.asSequence()).toCurrent()
        is X509Certificate -> LegacyX509Certificate.decodeFromTlv(element.asSequence()).toCurrent()
        is X509CertificateExtension -> LegacyX509CertificateExtension.decodeFromTlv(element.asSequence()).toCurrent()
        else -> error("No legacy regression decoder registered for ${value::class.simpleName}")
    }
}

internal fun decodeLegacyCertificateAsCurrent(encoded: ByteArray): X509Certificate =
    LegacyX509Certificate.decodeFromTlv(Asn1Element.parse(encoded).asSequence()).toCurrent()

private fun LegacyEcPrivateKeyInfo.toCurrent() =
    EcPrivateKeyInfo(
        version = version,
        privateKey = privateKey,
        parameters = parameters?.let(::ExplicitlyTagged),
        publicKey = publicKey?.let(::ExplicitlyTagged),
    )

private fun LegacyEncryptedPrivateKeyInfo.toCurrent() =
    EncryptedPrivateKeyInfo(
        encryptionAlgorithm = AlgorithmIdentifier(encryptionAlgorithm),
        encryptedData = encryptedData,
    )

private fun LegacyPkcs8PrivateKeyInfo.toCurrent() =
    Pkcs8PrivateKeyInfo(
        version = version,
        privateKeyAlgorithm = AlgorithmIdentifier(algorithmOid, algorithmParameters),
        privateKey = privateKey,
        attributes = attributes?.toSet(),
    )

private fun LegacyRsaOtherPrimeInfo.toCurrent() =
    RsaOtherPrimeInfo(
        prime = prime,
        exponent = exponent,
        coefficient = coefficient,
    )

private fun LegacyRsaPrivateKeyInfo.toCurrent() =
    RsaPrivateKeyInfo(
        version = version,
        modulus = modulus,
        publicExponent = publicExponent,
        privateExponent = privateExponent,
        prime1 = prime1,
        prime2 = prime2,
        exponent1 = exponent1,
        exponent2 = exponent2,
        coefficient = coefficient,
        otherPrimeInfos = otherPrimeInfos?.map { it.toCurrent() },
    )

private fun LegacyRsaPublicKeyInfo.toCurrent() =
    RsaPublicKeyInfo(
        modulus = modulus,
        publicExponent = publicExponent,
    )

private fun LegacySignatureAlgorithmIdentifier.toCurrent() =
    AlgorithmIdentifier(
        oid = oid,
        parameters = parameters,
    )

private fun LegacySignatureValue.toCurrent() = SignatureValue(rawBitString)

private fun LegacySubjectPublicKeyInfo.toCurrent() =
    SubjectPublicKeyInfo(
        algorithmIdentifier = AlgorithmIdentifier(algorithmOid, algorithmParameters),
        subjectPublicKey = subjectPublicKey,
    )

private fun LegacyAttribute.toCurrent() =
    Attribute(
        oid = oid,
        value = value.toSet(),
    )

private fun LegacyAttributeTypeAndValue.toCurrent() =
    AttributeTypeAndValue(
        oid = oid,
        value = value,
    )

private fun LegacyRelativeDistinguishedName.toCurrent() =
    X500RelativeDistinguishedName(attrsAndValues.map { it.toCurrent() }.toSet())

private fun LegacyPkcs10CertificationRequestInfo.toCurrent() =
    Pkcs10CertificationRequestInfo(
        rawVersion = version,
        subjectName = subjectName.map { it.toCurrent() },
        publicKey = publicKey.toCurrent(),
        attributes = attributes.map { it.toCurrent() },
    )

private fun LegacyPkcs10CertificationRequest.toCurrent() =
    Pkcs10CertificationRequest(
        certificationRequestInfo = certificationRequestInfo.toCurrent(),
        signatureAlgorithm = signatureAlgorithm.toCurrent(),
        signatureValue = signatureValue.toCurrent(),
    )

private fun LegacyX509CertificateExtension.toCurrent() =
    X509CertificateExtension(
        oid = oid,
        critical = critical.takeIf { it },
        value = value.asOctetString().content,
    )

private fun LegacyTbsCertificate.toCurrent() =
    TbsCertificate(
        version = version?.let { it+1 },
        serialNumber = serialNumber,
        signatureAlgorithm = signatureAlgorithm.toCurrent(),
        issuerName = issuerName.map { it.toCurrent() },
        validFrom = validFrom,
        validUntil = validUntil,
        subjectName = subjectName.map { it.toCurrent() },
        subjectPublicKeyInfo = subjectPublicKeyInfo.toCurrent(),
        issuerUniqueID = issuerUniqueID,
        subjectUniqueID = subjectUniqueID,
        extensions = extensions?.map { it.toCurrent() },
    )

private fun LegacyX509Certificate.toCurrent() =
    X509Certificate(
        tbsCertificate = tbsCertificate.toCurrent(),
        signatureAlgorithm = signatureAlgorithm.toCurrent(),
        signatureValue = signatureValue.toCurrent(),
    )
