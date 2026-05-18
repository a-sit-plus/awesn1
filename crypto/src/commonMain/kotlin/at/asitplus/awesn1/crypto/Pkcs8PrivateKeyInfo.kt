// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.decodeFromTlv
import at.asitplus.awesn1.serialization.encodeToTlv
import kotlinx.serialization.Serializable

/**
 *
 * As per [RFC5208](https://www.rfc-editor.org/rfc/rfc5208.html#section-5):
 * ```
 * PrivateKeyInfo ::= SEQUENCE {
 *   version                   Version,
 *   privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
 *   privateKey                PrivateKey,
 *   attributes           [0]  IMPLICIT Attributes OPTIONAL }
 *
 * Version ::= INTEGER
 * PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
 * PrivateKey ::= OCTET STRING
 * Attributes ::= SET OF Attribute
 * ```
 */
@Serializable
data class Pkcs8PrivateKeyInfo(
    override val rawVersion: Asn1Integer,
    val privateKeyAlgorithm: X509AlgorithmIdentifier,
    val privateKey: Asn1Element,
    @Asn1Tag(tagNumber = 0u)
    val attributes: Set<Asn1Element>? = null,
) : Versioned {
    val algorithmOid: ObjectIdentifier get() = privateKeyAlgorithm.oid
    val algorithmParameters: Asn1Element? get() = privateKeyAlgorithm.parameters

    /**
     *
     * [rawVersion] reopresents the encoded integer, (semantic) [version] denotes the
     * version commonly referred to as the version of a private key
     *
     * | RAW Version | (Semantic) Version |
     * |:-----------:|:----------------:|
     * | 0           | 1                |
     *
     * The integer must fit the valid Int value range (within [Int.MIN_VALUE]..[Int.MAX_VALUE]), otherwise a [NumberFormatException] will be thrown.
     *
     * Getter may throw but we cannot annotate due to https://youtrack.jetbrains.com/issue/KT-63047/Throws-annotation-on-getter-leads-to-compile-time-error-for-iOS-target
     */
    override val version: Int by lazy { rawVersion.toInt() + 1 }

    @Throws(Asn1Exception::class)
    fun decodeRsaPrivateKey(): Pkcs1RsaPrivateKeyInfo =
        DER.decodeFromTlv(privateKey.asEncapsulatingOctetString().decodeRethrowing { next() })

    @Throws(Asn1Exception::class)
    fun decodeEcPrivateKey(): Sec1EcPrivateKeyInfo =
        DER.decodeFromTlv(privateKey.asEncapsulatingOctetString().decodeRethrowing { next() })

    companion object {
        private val RSA_ENCRYPTION_OID = ObjectIdentifier("1.2.840.113549.1.1.1")
        private val EC_PUBLIC_KEY_OID = ObjectIdentifier("1.2.840.10045.2.1")

        fun rsa(privateKey: Pkcs1RsaPrivateKeyInfo, attributes: Set<Asn1Element>? = null): Pkcs8PrivateKeyInfo =
            Pkcs8PrivateKeyInfo(
                rawVersion = Asn1Integer.ZERO,
                privateKeyAlgorithm = X509AlgorithmIdentifier(RSA_ENCRYPTION_OID, listOf(Asn1.Null())),
                privateKey = Asn1.OctetStringEncapsulating { +DER.encodeToTlv(privateKey) },
                attributes = attributes,
            )

        fun ec(
            sec1Key: Sec1EcPrivateKeyInfo,
            curveOid: ObjectIdentifier?,
            attributes: Set<Asn1Element>? = null,
        ): Pkcs8PrivateKeyInfo = Pkcs8PrivateKeyInfo(
            rawVersion = Asn1Integer.ZERO,
            privateKeyAlgorithm = X509AlgorithmIdentifier(
                EC_PUBLIC_KEY_OID,
                curveOid?.let { listOf(it.encodeToTlv()) }.orEmpty(),
            ),
            privateKey = Asn1.OctetStringEncapsulating { +DER.encodeToTlv(sec1Key) },
            attributes = attributes,
        )
    }
}
