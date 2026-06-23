// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1Time
import at.asitplus.awesn1.crypto.*
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.awesn1.serialization.ExplicitlyTagged
import at.asitplus.awesn1.serialization.getValue
import kotlinx.serialization.Serializable

@Deprecated("Use X509TbsCertificate instead", ReplaceWith("X509TbsCertificate"))
typealias TbsCertificate = X509TbsCertificate

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
@ConsistentCopyVisibility
@Serializable
//CTOR internal for testing
data class X509TbsCertificate internal constructor(
    @Asn1Tag(tagNumber = 0u)
    private val taggedVersion: ExplicitlyTagged<Version>? = null,
    val serialNumber: Asn1Integer,
    val signatureAlgorithm: X509AlgorithmIdentifier,
    val issuerName: List<X500RelativeDistinguishedName>,
    val validity: Validity,
    val subjectName: List<X500RelativeDistinguishedName>,
    val subjectPublicKeyInfo: SubjectPublicKeyInfo,
    @Asn1Tag(tagNumber = 1u)
    val rawIssuerUniqueID: LenientBitString? = null,
    @Asn1Tag(tagNumber = 2u)
    val rawSubjectUniqueID: LenientBitString? = null,
    @Asn1Tag(tagNumber = 3u)
    private val taggedExtensions: ExplicitlyTagged<List<X509CertificateExtension>>? = null,
) {
    constructor(
        version: Version? = Version.V3,
        serialNumber: Asn1Integer,
        signatureAlgorithm: X509AlgorithmIdentifier,
        issuerName: List<X500RelativeDistinguishedName>,
        validFrom: Asn1Time.SecondsCapped,
        validUntil: Asn1Time.SecondsCapped,
        subjectName: List<X500RelativeDistinguishedName>,
        subjectPublicKeyInfo: SubjectPublicKeyInfo,
        issuerUniqueID: Asn1BitString? = null,
        subjectUniqueID: Asn1BitString? = null,
        extensions: List<X509CertificateExtension>? = null,
    ) : this(
        taggedVersion = version?.let { ExplicitlyTagged(it) },
        serialNumber = serialNumber,
        signatureAlgorithm = signatureAlgorithm,
        issuerName = issuerName,
        validity = Validity(validFrom, validUntil),
        subjectName = subjectName,
        subjectPublicKeyInfo = subjectPublicKeyInfo,
        rawIssuerUniqueID = issuerUniqueID?.let(::LenientBitString),
        rawSubjectUniqueID = subjectUniqueID?.let(::LenientBitString),
        taggedExtensions = extensions?.takeIf { it.isNotEmpty() }?.let(::ExplicitlyTagged),
    )

    val extensions: List<X509CertificateExtension>? by taggedExtensions

    /**
     * The raw value of the certificate version, useful if nullness of encoded version is needed.
     */
    val rawVersion: Version? by taggedVersion

    val version: Version get() = rawVersion ?: Version.V1

    /**
     * Getter may throw but we cannot annotate due to https://youtrack.jetbrains.com/issue/KT-63047/Throws-annotation-on-getter-leads-to-compile-time-error-for-iOS-target
     */
    val issuerUniqueID: Asn1BitString? by rawIssuerUniqueID

    /**
     * Getter may throw but we cannot annotate due to https://youtrack.jetbrains.com/issue/KT-63047/Throws-annotation-on-getter-leads-to-compile-time-error-for-iOS-target
     */
    val subjectUniqueID: Asn1BitString? by rawSubjectUniqueID

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is X509TbsCertificate) return false

        if (taggedVersion != other.taggedVersion) return false
        if (serialNumber != other.serialNumber) return false
        if (signatureAlgorithm != other.signatureAlgorithm) return false
        if (issuerName != other.issuerName) return false
        if (validity != other.validity) return false
        if (subjectName != other.subjectName) return false
        if (subjectPublicKeyInfo != other.subjectPublicKeyInfo) return false
        if (rawIssuerUniqueID != other.rawIssuerUniqueID) return false
        if (rawSubjectUniqueID != other.rawSubjectUniqueID) return false
        if (taggedExtensions != other.taggedExtensions) return false

        return true
    }

    override fun hashCode(): Int {
        var result = taggedVersion?.hashCode() ?: 0
        result = 31 * result + serialNumber.hashCode()
        result = 31 * result + signatureAlgorithm.hashCode()
        result = 31 * result + issuerName.hashCode()
        result = 31 * result + validity.hashCode()
        result = 31 * result + subjectName.hashCode()
        result = 31 * result + subjectPublicKeyInfo.hashCode()
        result = 31 * result + (rawIssuerUniqueID?.hashCode() ?: 0)
        result = 31 * result + (rawSubjectUniqueID?.hashCode() ?: 0)
        result = 31 * result + (taggedExtensions?.hashCode() ?: 0)
        return result
    }

    /**
     *
     *
     * | Encoded Version | (Semantic) Version |
     * |:---------------:|:----------------:|
     * | (absent)        | 1                |
     * | 0               | 1                |
     * | 1               | 2                |
     * | 2               | 3                |
     *
     */
    @Asn1Tag(tagNumber = 0x02uL, tagClass = Asn1Tag.Class.UNIVERSAL)
    enum class Version {
        V1, V2, V3
    }


}

/**
 * Non-throwing variant of [X509TbsCertificate.issuerUniqueID] that returns null if the bit string is malformed.
 */
val X509TbsCertificate.issuerUniqueIdOrNull: Asn1BitString? get() = rawIssuerUniqueID?.strictOrNull

/**
 * Non-throwing variant of [X509TbsCertificate.subjectUniqueID] that returns null if the bit string is malformed.
 */
val X509TbsCertificate.subjectUniqueIdOrNull: Asn1BitString? get() = rawSubjectUniqueID?.strictOrNull

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
