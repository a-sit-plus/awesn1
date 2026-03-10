// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.decodeRethrowing
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.decodeToInt
import at.asitplus.awesn1.readOid
import at.asitplus.awesn1.serialization.Asn1Serializable
import kotlinx.serialization.Serializable

@Serializable(with = PrivateKeyInfo.Companion::class)
open class PrivateKeyInfo(
    val version: Int,
    val privateKeyAlgorithm: Asn1Sequence,
    val privateKey: Asn1Element,
    val attributes: List<Asn1Element>? = null,
) : at.asitplus.awesn1.Asn1Encodable<Asn1Sequence> {

    val algorithmOid: ObjectIdentifier
        get() = (privateKeyAlgorithm.children.firstOrNull() as? Asn1Primitive)?.readOid()
            ?: throw Asn1Exception("PrivateKeyInfo algorithm identifier is empty")

    val algorithmParameters: List<Asn1Element>
        get() = privateKeyAlgorithm.children.drop(1)

    override fun encodeToTlv() = Asn1.Sequence {
        +Asn1.Int(version)
        +privateKeyAlgorithm
        +privateKey
        attributes?.let { attrs ->
            +(Asn1.SetOf {
                attrs.forEach { +it }
            } withImplicitTag 0uL)
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PrivateKeyInfo) return false
        return version == other.version &&
            privateKeyAlgorithm == other.privateKeyAlgorithm &&
            privateKey == other.privateKey &&
            attributes == other.attributes
    }

    override fun hashCode(): Int {
        var result = version
        result = 31 * result + privateKeyAlgorithm.hashCode()
        result = 31 * result + privateKey.hashCode()
        result = 31 * result + (attributes?.hashCode() ?: 0)
        return result
    }

    @Throws(Asn1Exception::class)
    fun decodeRsaPrivateKey(): RsaPrivateKey =
        RsaPrivateKey.decodeFromTlv(privateKey.asEncapsulatingOctetString().decodeRethrowing { next().asSequence() })

    @Throws(Asn1Exception::class)
    fun decodeEcPrivateKey(): EcPrivateKey =
        EcPrivateKey.decodeFromTlv(privateKey.asEncapsulatingOctetString().decodeRethrowing { next().asSequence() })

    companion object : Asn1Serializable<Asn1Sequence, PrivateKeyInfo> {
        override val leadingTags = setOf(Asn1Element.Tag.SEQUENCE)

        private val RSA_ENCRYPTION_OID = ObjectIdentifier("1.2.840.113549.1.1.1")
        private val EC_PUBLIC_KEY_OID = ObjectIdentifier("1.2.840.10045.2.1")

        fun rsa(privateKey: RsaPrivateKey, attributes: List<Asn1Element>? = null): PrivateKeyInfo = PrivateKeyInfo(
            version = 0,
            privateKeyAlgorithm = Asn1.Sequence {
                +RSA_ENCRYPTION_OID
                +Asn1.Null()
            },
            privateKey = Asn1.OctetStringEncapsulating { +privateKey.encodeToTlv() },
            attributes = attributes
        )

        fun ec(
            sec1Key: EcPrivateKey,
            curveOid: ObjectIdentifier?,
            attributes: List<Asn1Element>? = null
        ): PrivateKeyInfo = PrivateKeyInfo(
            version = 0,
            privateKeyAlgorithm = Asn1.Sequence {
                +EC_PUBLIC_KEY_OID
                curveOid?.let { +it }
            },
            privateKey = Asn1.OctetStringEncapsulating { +sec1Key.encodeToTlv() },
            attributes = attributes
        )

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): PrivateKeyInfo = src.decodeRethrowing {
            val version = next().asPrimitive().decodeToInt()
            val algorithm = next().asSequence()
            val privateKey = next()
            val attributes = if (hasNext()) {
                next().asSet().children
            } else {
                null
            }
            PrivateKeyInfo(version, algorithm, privateKey, attributes)
        }
    }
}
