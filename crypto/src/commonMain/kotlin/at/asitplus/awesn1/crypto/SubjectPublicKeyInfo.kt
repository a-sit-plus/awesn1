// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.decodeRethrowing
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.asAsn1BitString
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.encoding.readNull
import at.asitplus.awesn1.readOid
import at.asitplus.awesn1.serialization.Asn1Serializable
import kotlinx.serialization.Serializable

//TODO also register open poly using OID of algorithmidentifier
@Serializable(with = SubjectPublicKeyInfo.Companion::class)
open class SubjectPublicKeyInfo(
    val algorithmIdentifier: Asn1Sequence,
    val subjectPublicKey: Asn1BitString,
) : at.asitplus.awesn1.Asn1Encodable<Asn1Sequence> {

    val algorithmOid: ObjectIdentifier
        get() = (algorithmIdentifier.children.firstOrNull() as? Asn1Primitive)?.readOid()
            ?: throw Asn1Exception("SubjectPublicKeyInfo algorithm identifier is empty")

    val algorithmParameters: List<Asn1Element>
        get() = algorithmIdentifier.children.drop(1)

    override fun encodeToTlv() = Asn1.Sequence {
        +algorithmIdentifier
        +Asn1.BitString(subjectPublicKey.rawBytes)
    }

    @Throws(Asn1Exception::class)
    fun decodeRsaPublicKey(): RsaPublicKeyInfo {
        if (algorithmOid != RSA_ENCRYPTION_OID) {
            throw Asn1Exception("SubjectPublicKeyInfo is not an RSA public key")
        }
        require(algorithmParameters.size == 1) { "RSA SubjectPublicKeyInfo must contain NULL params" }
        algorithmParameters.single().asPrimitive().readNull()
        return RsaPublicKeyInfo.decodeFromTlv(Asn1Element.parse(subjectPublicKey.rawBytes).asSequence())
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SubjectPublicKeyInfo) return false
        return algorithmIdentifier == other.algorithmIdentifier && subjectPublicKey == other.subjectPublicKey
    }

    override fun hashCode(): Int = 31 * algorithmIdentifier.hashCode() + subjectPublicKey.hashCode()

    companion object : Asn1Serializable<Asn1Sequence, SubjectPublicKeyInfo> {
        override val leadingTags = setOf(Asn1Element.Tag.SEQUENCE)

        private val RSA_ENCRYPTION_OID = ObjectIdentifier("1.2.840.113549.1.1.1")
        private val EC_PUBLIC_KEY_OID = ObjectIdentifier("1.2.840.10045.2.1")

        fun rsa(publicKey: RsaPublicKeyInfo): SubjectPublicKeyInfo = SubjectPublicKeyInfo(
            algorithmIdentifier = Asn1.Sequence {
                +RSA_ENCRYPTION_OID
                +Asn1.Null()
            },
            subjectPublicKey = Asn1BitString(publicKey.encodeToTlv().derEncoded)
        )

        fun rsa(modulus: Asn1Integer, exponent: Asn1Integer): SubjectPublicKeyInfo = rsa(
            RsaPublicKeyInfo(
                modulus as Asn1Integer.Positive,
                exponent as Asn1Integer.Positive,
            )
        )

        fun ec(curveOid: ObjectIdentifier, ansiX963Key: ByteArray): SubjectPublicKeyInfo = SubjectPublicKeyInfo(
            algorithmIdentifier = Asn1.Sequence {
                +EC_PUBLIC_KEY_OID
                +curveOid
            },
            subjectPublicKey = Asn1BitString(ansiX963Key)
        )

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): SubjectPublicKeyInfo = src.decodeRethrowing {
            val algorithmIdentifier = next().asSequence()
            val bitString = next().asPrimitive().asAsn1BitString()
            SubjectPublicKeyInfo(algorithmIdentifier, bitString)
        }
    }
}
