// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.decodeRethrowing
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.serialization.Asn1ConstructedBit
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.awesn1.serialization.DER
import kotlinx.serialization.Serializable

@Serializable
data class Pkcs8PrivateKeyInfo(
    val version: Int,
    val privateKeyAlgorithm: AlgorithmIdentifier,
    val privateKey: Asn1Element,
    @Asn1Tag(tagNumber = 0u, constructed = Asn1ConstructedBit.CONSTRUCTED)
    val attributes: Set<Asn1Element>? = null,
) {
    val algorithmOid: ObjectIdentifier get() = privateKeyAlgorithm.oid
    val algorithmParameters: List<Asn1Element> get() = privateKeyAlgorithm.parameters

    @Throws(Asn1Exception::class)
    fun decodeRsaPrivateKey(): RsaPrivateKeyInfo =
        DER.decodeFromTlv(
            RsaPrivateKeyInfo.serializer(),
            privateKey.asEncapsulatingOctetString().decodeRethrowing { next() }
        )

    @Throws(Asn1Exception::class)
    fun decodeEcPrivateKey(): EcPrivateKeyInfo =
        DER.decodeFromTlv(
            EcPrivateKeyInfo.serializer(),
            privateKey.asEncapsulatingOctetString().decodeRethrowing { next() }
        )

    companion object {
        private val RSA_ENCRYPTION_OID = ObjectIdentifier("1.2.840.113549.1.1.1")
        private val EC_PUBLIC_KEY_OID = ObjectIdentifier("1.2.840.10045.2.1")

        fun rsa(privateKey: RsaPrivateKeyInfo, attributes: Set<Asn1Element>? = null): Pkcs8PrivateKeyInfo =
            Pkcs8PrivateKeyInfo(
                version = 0,
                privateKeyAlgorithm = AlgorithmIdentifier(RSA_ENCRYPTION_OID, listOf(Asn1.Null())),
                privateKey = Asn1.OctetStringEncapsulating {
                    +DER.encodeToTlv(RsaPrivateKeyInfo.serializer(), privateKey)
                },
                attributes = attributes,
            )

        fun ec(
            sec1Key: EcPrivateKeyInfo,
            curveOid: ObjectIdentifier?,
            attributes: Set<Asn1Element>? = null,
        ): Pkcs8PrivateKeyInfo = Pkcs8PrivateKeyInfo(
            version = 0,
            privateKeyAlgorithm = AlgorithmIdentifier(
                EC_PUBLIC_KEY_OID,
                curveOid?.let { listOf(it.encodeToTlv()) }.orEmpty(),
            ),
            privateKey = Asn1.OctetStringEncapsulating {
                +DER.encodeToTlv(EcPrivateKeyInfo.serializer(), sec1Key)
            },
            attributes = attributes,
        )
    }
}
