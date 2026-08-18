// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.Pkcs1RsaPublicKeyInfo.Companion.from
import at.asitplus.awesn1.crypto.Sec1EcPublicKeyInfo.Companion.from
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
 * @see Pkcs1RsaPublicKeyInfo.of
 * @see Sec1EcPublicKeyInfo.of
 */
@Serializable
data class SubjectPublicKeyInfo(
    val algorithmIdentifier: X509AlgorithmIdentifier,
    val subjectPublicKey: Asn1BitString,
) : WithPemLabel {

    val algorithmOid: ObjectIdentifier get() = algorithmIdentifier.oid
    val algorithmParameters: Asn1Element? get() = algorithmIdentifier.parameters

    override val pemLabel: String get() = PEM_LABEL_PUBLIC_KEY

    @Deprecated("Moved to a more suitable location", ReplaceWith("Pkcs1RsaPublicKeyInfo.of(this)"))
    fun decodeRsaPublicKey() = Pkcs1RsaPublicKeyInfo.of(this)

    companion object : PemLabelSpec<SubjectPublicKeyInfo> {
        const val PEM_LABEL_PUBLIC_KEY = "PUBLIC KEY"
        const val PEM_LABEL_RSA_PUBLIC_KEY = "RSA PUBLIC KEY"

        override val canonicalPemLabel: String get() = PEM_LABEL_PUBLIC_KEY
        override val alternativePemLabels: Set<String> = setOf(PEM_LABEL_RSA_PUBLIC_KEY)


        @Deprecated("Moved to a more suitable location",
            replaceWith = ReplaceWith("SubjectPublicKeyInfo.from(publicKey)"))
        fun rsa(publicKey: Pkcs1RsaPublicKeyInfo) = this.from(publicKey)

        @Deprecated("Passing x/y separately is preferred")
        fun ec(curveOid: ObjectIdentifier, ansiX963Key: ByteArray): SubjectPublicKeyInfo = runRethrowing {
            from(Sec1EcPublicKeyInfo(curveOid, ansiX963Key))
        }

    }
}
