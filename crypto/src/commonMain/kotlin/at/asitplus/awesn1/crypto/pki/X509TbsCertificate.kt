// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1Time
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.awesn1.serialization.ExplicitlyTagged
import at.asitplus.awesn1.toInt
import kotlinx.serialization.Serializable

/**
 *
 * As per [RFC5280](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1):
 *
 * ```
 * TBSCertificate  ::=  SEQUENCE  {
 *         version         [0]  EXPLICIT Version DEFAULT v1,
 *         serialNumber         CertificateSerialNumber,
 *         signature            AlgorithmIdentifier,
 *         issuer               Name,
 *         validity             Validity,
 *         subject              Name,
 *         subjectPublicKeyInfo SubjectPublicKeyInfo,
 *         issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
 *                              -- If present, version MUST be v2 or v3
 *
 *         subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
 *                              -- If present, version MUST be v2 or v3
 *         extensions      [3]  EXPLICIT Extensions OPTIONAL
 *                              -- If present, version MUST be v3
 *         }
 *
 *    Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
 *
 *    CertificateSerialNumber  ::=  INTEGER
 *
 *    Name ::= CHOICE { -- only one possibility for now --
 *       rdnSequence  RDNSequence }
 *
 *   RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 *
 *    Validity ::= SEQUENCE {
 *         notBefore      Time,
 *         notAfter       Time }
 *
 *    Time ::= CHOICE {
 *         utcTime        UTCTime,
 *         generalTime    GeneralizedTime }
 *
 *    UniqueIdentifier  ::=  BIT STRING
 *
 *    SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *         algorithm            AlgorithmIdentifier,
 *         subjectPublicKey     BIT STRING  }
 *
 *    Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
 *
 *    Extension  ::=  SEQUENCE  {
 *         extnID      OBJECT IDENTIFIER,
 *         critical    BOOLEAN DEFAULT FALSE,
 *         extnValue   OCTET STRING
 *                     -- contains the DER encoding of an ASN.1 value
 *                     -- corresponding to the extension type identified
 *                     -- by extnID
 *         }
 * ```
 *
 */
@Serializable
data class X509TbsCertificate(
    @Asn1Tag(tagNumber = 0u)
    val rawVersion: ExplicitlyTagged<Asn1Integer>? = null,
    val serialNumber: Asn1Integer,
    val signatureAlgorithm: X509AlgorithmIdentifier,
    val issuerName: List<X500RelativeDistinguishedName>,
    val validity: Validity,
    val subjectName: List<X500RelativeDistinguishedName>,
    val subjectPublicKeyInfo: SubjectPublicKeyInfo,
    @Asn1Tag(tagNumber = 1u)
    val issuerUniqueID: Asn1BitString? = null,
    @Asn1Tag(tagNumber = 2u)
    val subjectUniqueID: Asn1BitString? = null,
    @Asn1Tag(tagNumber = 3u)
    val extensions: ExplicitlyTagged<List<X509CertificateExtension>>? = null,
) {
    constructor(
        version: Int? = null,
        serialNumber: Asn1Integer,
        signatureAlgorithm: X509AlgorithmIdentifier,
        issuerName: List<X500RelativeDistinguishedName>,
        validFrom: Asn1Time,
        validUntil: Asn1Time,
        subjectName: List<X500RelativeDistinguishedName>,
        subjectPublicKeyInfo: SubjectPublicKeyInfo,
        issuerUniqueID: Asn1BitString? = null,
        subjectUniqueID: Asn1BitString? = null,
        extensions: List<X509CertificateExtension>? = null,
    ) : this(
        rawVersion = version?.let { ExplicitlyTagged(Asn1Integer(it - 1)) },
        serialNumber = serialNumber,
        signatureAlgorithm = signatureAlgorithm,
        issuerName = issuerName,
        validity = Validity(validFrom, validUntil),
        subjectName = subjectName,
        subjectPublicKeyInfo = subjectPublicKeyInfo,
        issuerUniqueID = issuerUniqueID,
        subjectUniqueID = subjectUniqueID,
        extensions = extensions?.takeIf { it.isNotEmpty() }?.let(::ExplicitlyTagged),
    )

    /**
     *
     * [rawVersion] reopresents the encoded integer, (semantic) version denotes the
     * version commonly referred to as the version of a certificate
     *
     * | RAW Version | (Semantic) Version |
     * |:-----------:|:----------------:|
     * | 0           | 1                |
     * | 1           | 2                |
     * | 2           | 3                |
     *
     * The integer must fit the valid Int value range (within Int.MIN_VALUE..Int.MAX_VALUE), otherwise a [NumberFormatException] will be thrown.
     */
    @get:Throws(NumberFormatException::class)
    val version: Int? by lazy { rawVersion?.value?.toInt()?.let { it + 1 } ?: 1 }

    /**
     * @see version
     */
    val semanticVersion: Int? get() = version
}


/**
 * As per [RFC5280](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1):
 *
 * ```
 *    Validity ::= SEQUENCE {
 *         notBefore      Time,
 *         notAfter       Time }
 *
 *    Time ::= CHOICE {
 *         utcTime        UTCTime,
 *         generalTime    GeneralizedTime }
 *  ```
 *
 */
@Serializable
data class Validity(
    val validFrom: Asn1Time,
    val validUntil: Asn1Time,
)
