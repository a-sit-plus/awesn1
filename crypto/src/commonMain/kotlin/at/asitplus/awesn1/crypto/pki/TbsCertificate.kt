// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1Time
import at.asitplus.awesn1.crypto.SignatureAlgorithmIdentifier
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.awesn1.serialization.Asn1ConstructedBit
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.awesn1.serialization.ExplicitlyTagged
import kotlinx.serialization.Serializable

@Serializable
data class TbsCertificate(
    @Asn1Tag(tagNumber = 0u, constructed = Asn1ConstructedBit.CONSTRUCTED)
    val version: ExplicitlyTagged<Int>? = null,
    val serialNumber: Asn1Integer,
    val signatureAlgorithm: SignatureAlgorithmIdentifier,
    val issuerName: List<RelativeDistinguishedName>,
    val validity: Validity,
    val subjectName: List<RelativeDistinguishedName>,
    val subjectPublicKeyInfo: SubjectPublicKeyInfo,
    @Asn1Tag(tagNumber = 1u, constructed = Asn1ConstructedBit.PRIMITIVE)
    val issuerUniqueID: Asn1BitString? = null,
    @Asn1Tag(tagNumber = 2u, constructed = Asn1ConstructedBit.PRIMITIVE)
    val subjectUniqueID: Asn1BitString? = null,
    @Asn1Tag(tagNumber = 3u, constructed = Asn1ConstructedBit.CONSTRUCTED)
    val extensions: ExplicitlyTagged<List<X509CertificateExtension>>? = null,
) {
    constructor(
        version: Int? = 2,
        serialNumber: ByteArray,
        signatureAlgorithm: SignatureAlgorithmIdentifier,
        issuerName: List<RelativeDistinguishedName>,
        validFrom: Asn1Time,
        validUntil: Asn1Time,
        subjectName: List<RelativeDistinguishedName>,
        subjectPublicKeyInfo: SubjectPublicKeyInfo,
        issuerUniqueID: Asn1BitString? = null,
        subjectUniqueID: Asn1BitString? = null,
        extensions: List<X509CertificateExtension>? = null,
    ) : this(
        version = version?.let(::ExplicitlyTagged),
        serialNumber = Asn1Integer.fromTwosComplement(serialNumber),
        signatureAlgorithm = signatureAlgorithm,
        issuerName = issuerName,
        validity = Validity(validFrom, validUntil),
        subjectName = subjectName,
        subjectPublicKeyInfo = subjectPublicKeyInfo,
        issuerUniqueID = issuerUniqueID,
        subjectUniqueID = subjectUniqueID,
        extensions = extensions?.takeIf { it.isNotEmpty() }?.let(::ExplicitlyTagged),
    )
}

@Serializable
data class Validity(
    val validFrom: Asn1Time,
    val validUntil: Asn1Time,
)
