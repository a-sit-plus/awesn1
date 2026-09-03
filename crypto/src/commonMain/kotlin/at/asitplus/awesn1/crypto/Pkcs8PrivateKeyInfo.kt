// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.Pkcs1RsaPrivateKeyInfo.Companion.invoke
import at.asitplus.awesn1.crypto.Sec1EcPrivateKeyInfo.Companion.invoke
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
 * @see Pkcs1RsaPrivateKeyInfo.of
 * @see Sec1EcPrivateKeyInfo.of
 */
@Serializable
data class Pkcs8PrivateKeyInfo(
    val version: Version,
    val privateKeyAlgorithm: X509AlgorithmIdentifier,
    val privateKey: Asn1OctetString,
    @Asn1Tag(tagNumber = 0u)
    val attributes: Set<Asn1Element>? = null,
) : WithPemLabel {

    // default Version
    constructor(
        privateKeyAlgorithm: X509AlgorithmIdentifier, privateKey: Asn1OctetString, attributes: Set<Asn1Element>? = null)
    : this(Version.V1, privateKeyAlgorithm, privateKey, attributes)

    val algorithmOid: ObjectIdentifier get() = privateKeyAlgorithm.oid
    val algorithmParameters: Asn1Element? get() = privateKeyAlgorithm.parameters

    override val pemLabel: String get() = PEM_LABEL_PRIVATE_KEY

    @Deprecated("Moved to a more suitable location", ReplaceWith("Pkcs1RsaPrivateKeyInfo.of(this)"))
    fun decodeRsaPrivateKey() =
        Pkcs1RsaPrivateKeyInfo.of(this)

    @Deprecated("Moved to a more suitable location", ReplaceWith("Sec1EcPrivateKeyInfo.of(this)"))
    fun decodeEcPrivateKey(): Sec1EcPrivateKeyInfo =
        Sec1EcPrivateKeyInfo.of(this)

    companion object : PemLabelSpec<Pkcs8PrivateKeyInfo> {

        const val PEM_LABEL_PRIVATE_KEY = "PRIVATE KEY"
        const val PEM_LABEL_RSA_PRIVATE_KEY = Pkcs1RsaPrivateKeyInfo.PEM_LABEL
        const val PEM_LABEL_EC_PRIVATE_KEY = Sec1EcPrivateKeyInfo.PEM_LABEL

        override val canonicalPemLabel: String = PEM_LABEL_PRIVATE_KEY
        override val alternativePemLabels: Set<String> =
            setOf(PEM_LABEL_RSA_PRIVATE_KEY, PEM_LABEL_EC_PRIVATE_KEY)

        @Deprecated("Moved to an extension on Pkcs1RsaPrivateKeyInfo's companion",
            ReplaceWith("Pkcs8PrivateKeyInfo(privateKey, attributes)"))
        fun rsa(privateKey: Pkcs1RsaPrivateKeyInfo, attributes: Set<Asn1Element>? = null) =
            this(privateKey, attributes)

        @Deprecated("Moved to an extension on Sec1EcPrivateKeyInfo's companion",
            ReplaceWith("Pkcs8PrivateKeyInfo(sec1Key, curveOid, attributes)"))
        fun ec(sec1Key: Sec1EcPrivateKeyInfo, curveOid: ObjectIdentifier?, attributes: Set<Asn1Element>? = null) =
            this(sec1Key, curveOid, attributes)
    }

    /**
     * | Encoded Version | Semantic Version |
     * |:---------------:|:----------------:|
     * | 0               | V1                |
     */
    @Asn1Tag(tagNumber = 0x02uL, tagClass = Asn1Tag.Class.UNIVERSAL)
    enum class Version {
        V1
    }
}
