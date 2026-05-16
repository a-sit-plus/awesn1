// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.encoding.readNull
import at.asitplus.awesn1.serialization.DER
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
) : WithPemLabel {

    init {
        if (subjectPublicKey.numPaddingBits != 0.toByte()) {
            throw Asn1Exception("Public key value must not have padding bits")
        }
    }

    val algorithmOid: ObjectIdentifier get() = algorithmIdentifier.oid
    val algorithmParameters: Asn1Element? get() = algorithmIdentifier.parameters

    override val pemLabel: String get() = canonicalPemLabel

    @Throws(Asn1Exception::class)
    fun decodeRsaPublicKey(): Pkcs1RsaPublicKeyInfo {
        if (algorithmOid != RSA_ENCRYPTION_OID) {
            throw Asn1Exception("SubjectPublicKeyInfo is not an RSA public key")
        }
        requireNotNull(algorithmParameters) { "RSA SubjectPublicKeyInfo must contain NULL params" }
        algorithmParameters!!.asPrimitive().readNull()
        return DER.decodeFromTlv(Pkcs1RsaPublicKeyInfo.serializer(), Asn1Element.parse(subjectPublicKey.rawBytes))
    }

    companion object : PemLabelSpec<SubjectPublicKeyInfo> {
        private val RSA_ENCRYPTION_OID = ObjectIdentifier("1.2.840.113549.1.1.1")
        private val EC_PUBLIC_KEY_OID = ObjectIdentifier("1.2.840.10045.2.1")

        const val PEM_LABEL_PUBLIC_KEY = "PUBLIC KEY"
        const val PEM_LABEL_RSA_PUBLIC_KEY = "RSA PUBLIC KEY"

        override val canonicalPemLabel: String get() = PEM_LABEL_PUBLIC_KEY
        override val validPemLabels: Set<String> = setOf(canonicalPemLabel, PEM_LABEL_RSA_PUBLIC_KEY)


        fun rsa(publicKey: Pkcs1RsaPublicKeyInfo): SubjectPublicKeyInfo = SubjectPublicKeyInfo(
            algorithmIdentifier = X509AlgorithmIdentifier(
                RSA_ENCRYPTION_OID,
                listOf(Asn1.Null())
            ),
            subjectPublicKey = Asn1BitString(DER.encodeToTlv(Pkcs1RsaPublicKeyInfo.serializer(), publicKey).derEncoded)
        )

        fun rsa(modulus: Asn1Integer, exponent: Asn1Integer): SubjectPublicKeyInfo =
            rsa(Pkcs1RsaPublicKeyInfo(modulus, exponent))

        fun ec(curveOid: ObjectIdentifier, ansiX963Key: ByteArray): SubjectPublicKeyInfo = SubjectPublicKeyInfo(
            algorithmIdentifier = X509AlgorithmIdentifier(EC_PUBLIC_KEY_OID, listOf(curveOid.encodeToTlv())),
            subjectPublicKey = Asn1BitString(ansiX963Key)
        )
    }
}
