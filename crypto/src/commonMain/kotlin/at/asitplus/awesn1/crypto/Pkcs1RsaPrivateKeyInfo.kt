// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1Null
import at.asitplus.awesn1.Asn1OctetString
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.awesn1.WithPemLabel
import at.asitplus.awesn1.PemLabelSpec
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.runRethrowing
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Der
import at.asitplus.awesn1.serialization.decodeFromDer
import at.asitplus.awesn1.serialization.decodeFromTlv
import at.asitplus.awesn1.serialization.encodeToTlv
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToByteArray

/**
 *
 * As per [RFC8017](https://www.rfc-editor.org/rfc/rfc8017.html#appendix-A.1.2):
 * ```
 * RSAPrivateKey ::= SEQUENCE {
 *   version           Version,
 *   modulus           INTEGER,
 *   publicExponent    INTEGER,
 *   privateExponent   INTEGER,
 *   prime1            INTEGER,
 *   prime2            INTEGER,
 *   exponent1         INTEGER,
 *   exponent2         INTEGER,
 *   coefficient       INTEGER,
 *   otherPrimeInfos   OtherPrimeInfos OPTIONAL
 * }
 * ```
 */
@Serializable
data class Pkcs1RsaPrivateKeyInfo(
    val version: Version,
    val modulus: Asn1Integer.Positive,
    val publicExponent: Asn1Integer.Positive,
    val privateExponent: Asn1Integer.Positive,
    val prime1: Asn1Integer.Positive,
    val prime2: Asn1Integer.Positive,
    val exponent1: Asn1Integer.Positive,
    val exponent2: Asn1Integer.Positive,
    val coefficient: Asn1Integer.Positive,
    val otherPrimeInfos: List<Pkcs1RsaOtherPrimeInfo>? = null,
) : WithPemLabel {
    /**
     * Corresponds verbatim to [RFC8017](https://www.rfc-editor.org/rfc/rfc8017.html#appendix-A.1.2):
     *
     *  version is the version number, for compatibility with future
     *       revisions of this document.  It SHALL be 0 for this version of the
     *       document, unless multi-prime is used; in which case, it SHALL be
     *       1.
     *
     *             Version ::= INTEGER { two-prime(0), multi(1) }
     *                (CONSTRAINED BY
     *                {-- version must be multi if otherPrimeInfos present --})
     */
    @Asn1Tag(tagNumber = 0x02uL, tagClass = Asn1Tag.Class.UNIVERSAL)
    enum class Version {
        TWO_PRIME, MULTI
    }

    override val pemLabel: String get() = PEM_LABEL
    companion object : PemLabelSpec<Pkcs1RsaPrivateKeyInfo> {
        const val PEM_LABEL = "RSA PRIVATE KEY"
        override val canonicalPemLabel: String get() = PEM_LABEL
        private val RSA_ENCRYPTION_OID = ObjectIdentifier("1.2.840.113549.1.1.1")

        fun of(privateKeyInfo: Pkcs8PrivateKeyInfo, der: Der = DER) = runRethrowing {
            require(privateKeyInfo.algorithmOid == RSA_ENCRYPTION_OID)
                { "Pkcs8PrivateKeyInfo is not an RSA private key" }
            require(privateKeyInfo.algorithmParameters == Asn1Null)
                { "RSA SubjectPublicKeyInfo must contain NULL params" }
            der.decodeFromTlv<Pkcs1RsaPrivateKeyInfo>(
                privateKeyInfo.privateKey.asEncapsulatingOctetString().element)
        }

        operator fun Pkcs8PrivateKeyInfo.Companion.invoke(
                privateKey: Pkcs1RsaPrivateKeyInfo, attributes: Set<Asn1Element>? = null, der: Der = DER
        ) = runRethrowing {
            Pkcs8PrivateKeyInfo(
                version = Pkcs8PrivateKeyInfo.Version.V1,
                privateKeyAlgorithm = X509AlgorithmIdentifier(RSA_ENCRYPTION_OID, Asn1Null),
                privateKey = Asn1OctetString(der.encodeToByteArray(privateKey)),
                attributes = attributes,
            )
        }
    }
}

