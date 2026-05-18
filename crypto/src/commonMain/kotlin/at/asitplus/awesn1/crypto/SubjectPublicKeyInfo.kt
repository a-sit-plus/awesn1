// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.encoding.readNull
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.decodeFromTlv
import at.asitplus.awesn1.serialization.encodeToTlv
import kotlinx.serialization.Serializable

/**
 * As per [RFC5280](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1):
 *
 * ```
 * SubjectPublicKeyInfo ::= SEQUENCE {
 *   algorithm         AlgorithmIdentifier,
 *   subjectPublicKey  BIT STRING
 * }
 * ```
 */
@Serializable
data class SubjectPublicKeyInfo(
    val algorithmIdentifier: X509AlgorithmIdentifier,
    val subjectPublicKey: Asn1BitString,
) {
    val algorithmOid: ObjectIdentifier get() = algorithmIdentifier.oid
    val algorithmParameters: Asn1Element? get() = algorithmIdentifier.parameters

    @Throws(Asn1Exception::class)
    fun decodeRsaPublicKey(): RsaPublicKeyInfo {
        if (algorithmOid != RSA_ENCRYPTION_OID) {
            throw Asn1Exception("SubjectPublicKeyInfo is not an RSA public key")
        }
        requireNotNull(algorithmParameters) { "RSA SubjectPublicKeyInfo must contain NULL params" }
        algorithmParameters!!.asPrimitive().readNull()
        return DER.decodeFromTlv( Asn1Element.parse(subjectPublicKey.rawBytes))
    }

    companion object {
        private val RSA_ENCRYPTION_OID = ObjectIdentifier("1.2.840.113549.1.1.1")
        private val EC_PUBLIC_KEY_OID = ObjectIdentifier("1.2.840.10045.2.1")

        fun rsa(publicKey: RsaPublicKeyInfo): SubjectPublicKeyInfo = SubjectPublicKeyInfo(
            algorithmIdentifier = X509AlgorithmIdentifier(
                RSA_ENCRYPTION_OID,
                listOf(Asn1.Null())
            ),
            subjectPublicKey = Asn1BitString(DER.encodeToTlv(publicKey).derEncoded)
        )

        fun rsa(modulus: Asn1Integer, exponent: Asn1Integer): SubjectPublicKeyInfo =
            rsa(RsaPublicKeyInfo(modulus, exponent))

        fun ec(curveOid: ObjectIdentifier, ansiX963Key: ByteArray): SubjectPublicKeyInfo = SubjectPublicKeyInfo(
            algorithmIdentifier = X509AlgorithmIdentifier(EC_PUBLIC_KEY_OID, listOf(curveOid.encodeToTlv())),
            subjectPublicKey = Asn1BitString(ansiX963Key)
        )
    }
}
