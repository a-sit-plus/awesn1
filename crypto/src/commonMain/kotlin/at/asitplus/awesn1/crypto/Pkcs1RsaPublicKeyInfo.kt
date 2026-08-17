// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1Null
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.WithPemLabel
import at.asitplus.awesn1.PemLabelSpec
import at.asitplus.awesn1.runRethrowing
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Der
import at.asitplus.awesn1.serialization.decodeFromDer
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToByteArray

/**
 *
 * As per [RFC8017](https://www.rfc-editor.org/rfc/rfc8017.html#appendix-A.1.1):
 * ```
 * RSAPublicKey ::= SEQUENCE {
 *   modulus           INTEGER,
 *   publicExponent    INTEGER
 * }
 * ```
 */
@Serializable
data class Pkcs1RsaPublicKeyInfo(
    val modulus: Asn1Integer,
    val publicExponent: Asn1Integer,
) : WithPemLabel {
    override val pemLabel: String get() = PEM_LABEL

    companion object : PemLabelSpec<Pkcs1RsaPublicKeyInfo> {
        const val PEM_LABEL = "RSA PUBLIC KEY"
        override val canonicalPemLabel: String get() = PEM_LABEL

        private val RSA_ENCRYPTION_OID = ObjectIdentifier("1.2.840.113549.1.1.1")

        fun of(publicKeyInfo: SubjectPublicKeyInfo, der: Der = DER) = runRethrowing {
            require(publicKeyInfo.algorithmOid == RSA_ENCRYPTION_OID)
                { "SubjectPublicKeyInfo is not an RSA public key" }
            require(publicKeyInfo.algorithmParameters == Asn1Null)
                { "RSA SubjectPublicKeyInfo must contain NULL params" }
            require (publicKeyInfo.subjectPublicKey.numPaddingBits == 0.toByte())
                { "RSA SubjectPublicKeyInfo must have full octets (no padding bits)" }
            der.decodeFromDer<Pkcs1RsaPublicKeyInfo>(publicKeyInfo.subjectPublicKey.bitCarryingBytes)
        }

        operator fun SubjectPublicKeyInfo.Companion.invoke(publicKey: Pkcs1RsaPublicKeyInfo, der: Der = DER) = runRethrowing {
            SubjectPublicKeyInfo(
                X509AlgorithmIdentifier(RSA_ENCRYPTION_OID, Asn1Null),
                Asn1BitString(der.encodeToByteArray(publicKey))
            )
        }

        fun SubjectPublicKeyInfo.Companion.rsa(modulus: Asn1Integer, exponent: Asn1Integer, der: Der = DER) =
            runRethrowing { invoke(Pkcs1RsaPublicKeyInfo(modulus, exponent), der) }
    }
}
