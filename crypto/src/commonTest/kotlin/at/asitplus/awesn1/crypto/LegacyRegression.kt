package at.asitplus.awesn1.crypto
import at.asitplus.awesn1.Asn1Time

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1Integer.Sign
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
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
import at.asitplus.awesn1.crypto.pki.Pkcs10CsrAttribute
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequest
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequestInfo
import at.asitplus.awesn1.crypto.pki.X500Name
import at.asitplus.awesn1.crypto.pki.X500RelativeDistinguishedName
import at.asitplus.awesn1.crypto.pki.X509TbsCertificate
import at.asitplus.awesn1.crypto.pki.X509Certificate
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension
import at.asitplus.awesn1.serialization.ExplicitlyTagged
import at.asitplus.awesn1.runWrappingAs
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.decodeFromTlv
import kotlinx.serialization.SerializationException
import kotlinx.serialization.decodeFromByteArray

internal fun decodeLegacyAsCurrent(value: Any, encoded: ByteArray): Any {
    val element = Asn1Element.parse(encoded)
    return when (value) {
        is Sec1EcPrivateKeyInfo -> LegacyEcPrivateKeyInfo.decodeFromTlv(element.asSequence()).toCurrent()
        is EncryptedPrivateKeyInfo -> LegacyEncryptedPrivateKeyInfo.decodeFromTlv(element.asSequence()).toCurrent()
        is Pkcs8PrivateKeyInfo -> LegacyPkcs8PrivateKeyInfo.decodeFromTlv(element.asSequence()).toCurrent()
        is Pkcs1RsaOtherPrimeInfo -> LegacyRsaOtherPrimeInfo.decodeFromTlv(element.asSequence()).toCurrent()
        is Pkcs1RsaPrivateKeyInfo -> LegacyRsaPrivateKeyInfo.decodeFromTlv(element.asSequence()).toCurrent()
        is Pkcs1RsaPublicKeyInfo -> LegacyRsaPublicKeyInfo.decodeFromTlv(element.asSequence()).toCurrent()
        is X509AlgorithmIdentifier -> LegacySignatureAlgorithmIdentifier.decodeFromTlv(element.asSequence()).toCurrent()
        is X509SignatureValue -> LegacySignatureValue.decodeFromTlv(element.asPrimitive()).toCurrent()
        is SubjectPublicKeyInfo -> LegacySubjectPublicKeyInfo.decodeFromTlv(element.asSequence()).toCurrent()
        is Pkcs10CsrAttribute -> LegacyAttribute.decodeFromTlv(element.asSequence()).toCurrent()
        is X500AttributeTypeAndValue -> LegacyAttributeTypeAndValue.decodeFromTlv(element.asSequence()).toCurrent()
        is Pkcs10CertificationRequest -> LegacyPkcs10CertificationRequest.decodeFromTlv(element.asSequence())
            .toCurrent()

        is Pkcs10CertificationRequestInfo -> LegacyPkcs10CertificationRequestInfo.decodeFromTlv(element.asSequence())
            .toCurrent()

        is X500RelativeDistinguishedName -> LegacyRelativeDistinguishedName.decodeFromTlv(element.asSet()).toCurrent()
        is X509TbsCertificate -> LegacyTbsCertificate.decodeFromTlv(element.asSequence()).toCurrent()
        is X509Certificate -> LegacyX509Certificate.decodeFromTlv(element.asSequence()).toCurrent()
        is X509CertificateExtension -> LegacyX509CertificateExtension.decodeFromTlv(element.asSequence()).toCurrent()
        else -> error("No legacy regression decoder registered for ${value::class.simpleName}")
    }
}

internal fun decodeLegacyCertificateAsCurrent(encoded: ByteArray): X509Certificate =  runWrappingAs(::SerializationException) {
    LegacyX509Certificate.decodeFromTlv(Asn1Element.parse(encoded).asSequence()).toCurrent()
}

private fun LegacyEcPrivateKeyInfo.toCurrent() =
    Sec1EcPrivateKeyInfo(
        version = Sec1EcPrivateKeyInfo.Version.V1,
        privateKey = privateKey,
        taggedParameters = parameters?.let(::ExplicitlyTagged),
        taggedPublicKey = publicKey?.let(::ExplicitlyTagged),
    )

private fun LegacyEncryptedPrivateKeyInfo.toCurrent() =
    EncryptedPrivateKeyInfo(
        encryptionAlgorithm = X509AlgorithmIdentifier(encryptionAlgorithm),
        encryptedData = encryptedData,
    )

private fun LegacyPkcs8PrivateKeyInfo.toCurrent() =
    Pkcs8PrivateKeyInfo(
        version = Pkcs8PrivateKeyInfo.Version.V1,
        privateKeyAlgorithm = X509AlgorithmIdentifier(algorithmOid, algorithmParameters.singleOrNull()),
        privateKey = privateKey.asOctetString(),
        attributes = attributes?.toSet(),
    )

private fun LegacyRsaOtherPrimeInfo.toCurrent() =
    Pkcs1RsaOtherPrimeInfo(
        prime = prime as Asn1Integer.Positive,
        exponent = exponent as Asn1Integer.Positive,
        coefficient = coefficient as Asn1Integer.Positive,
    )

private fun LegacyRsaPrivateKeyInfo.toCurrent() =
    Pkcs1RsaPrivateKeyInfo(
        version = if (version == 0) Pkcs1RsaPrivateKeyInfo.Version.TWO_PRIME else Pkcs1RsaPrivateKeyInfo.Version.MULTI,
        modulus = modulus as Asn1Integer.Positive,
        publicExponent = publicExponent as Asn1Integer.Positive,
        privateExponent = privateExponent as Asn1Integer.Positive,
        prime1 = prime1 as Asn1Integer.Positive,
        prime2 = prime2 as Asn1Integer.Positive,
        exponent1 = exponent1 as Asn1Integer.Positive,
        exponent2 = exponent2 as Asn1Integer.Positive,
        coefficient = coefficient as Asn1Integer.Positive,
        otherPrimeInfos = otherPrimeInfos?.map { it.toCurrent() },
    )

private fun LegacyRsaPublicKeyInfo.toCurrent() =
    Pkcs1RsaPublicKeyInfo(
        modulus = modulus,
        publicExponent = publicExponent,
    )

private fun LegacySignatureAlgorithmIdentifier.toCurrent() =
    X509AlgorithmIdentifier(
        oid = oid,
        parameters = parameters.singleOrNull(),
    )

private fun LegacySignatureValue.toCurrent() = X509SignatureValue(rawBitString)

private fun LegacySubjectPublicKeyInfo.toCurrent() =
    SubjectPublicKeyInfo(
        algorithmIdentifier = X509AlgorithmIdentifier(algorithmOid, algorithmParameters.singleOrNull()),
        subjectPublicKey = subjectPublicKey,
    )

private fun LegacyAttribute.toCurrent() =
    Pkcs10CsrAttribute(
        oid = oid,
        value = value.toSet(),
    )

private fun LegacyAttributeTypeAndValue.toCurrent() =
    X500AttributeTypeAndValue(
        oid = oid,
        value = value,
    )

private fun LegacyRelativeDistinguishedName.toCurrent() =
    X500RelativeDistinguishedName(attrsAndValues.map { it.toCurrent() }.toSet())

private fun LegacyPkcs10CertificationRequestInfo.toCurrent() =DER.decodeFromTlv<Pkcs10CertificationRequestInfo>(encodeToTlv())

private fun LegacyPkcs10CertificationRequest.toCurrent() =
    Pkcs10CertificationRequest(
        certificationRequestInfo = certificationRequestInfo.toCurrent(),
        signatureAlgorithm = signatureAlgorithm.toCurrent(),
        signatureValue = signatureValue.toCurrent(),
    )

private fun LegacyX509CertificateExtension.toCurrent() =
    X509CertificateExtension(
        oid = oid,
        critical = critical,
        value = value.asOctetString().content,
    )

private fun LegacyTbsCertificate.toCurrent() =
    DER.decodeFromByteArray<X509TbsCertificate>(encodeToTlv().derEncoded)

private fun LegacyX509Certificate.toCurrent() =
    X509Certificate(
        tbsCertificate = tbsCertificate.toCurrent(),
        signatureAlgorithm = signatureAlgorithm.toCurrent(),
        signatureValue = signatureValue.toCurrent(),
    )
