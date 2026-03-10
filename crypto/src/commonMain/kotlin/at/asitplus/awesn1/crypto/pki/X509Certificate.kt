// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.decodeRethrowing
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.crypto.SignatureAlgorithmIdentifier
import at.asitplus.awesn1.serialization.Asn1Serializable
import kotlinx.serialization.Serializable

@Serializable(with = X509Certificate.Companion::class)
open class X509Certificate(
    val tbsCertificate: TbsCertificate,
    val signatureAlgorithm: SignatureAlgorithmIdentifier,
    val signatureValue: Asn1BitString,
) : at.asitplus.awesn1.Asn1PemEncodable<Asn1Sequence> {

    override val pemLabel: String = "CERTIFICATE"

    override fun encodeToTlv() = Asn1.Sequence {
        +tbsCertificate
        +signatureAlgorithm
        +Asn1.BitString(signatureValue.rawBytes)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is X509Certificate) return false
        return tbsCertificate == other.tbsCertificate &&
            signatureAlgorithm == other.signatureAlgorithm &&
            signatureValue == other.signatureValue
    }

    override fun hashCode(): Int {
        var result = tbsCertificate.hashCode()
        result = 31 * result + signatureAlgorithm.hashCode()
        result = 31 * result + signatureValue.hashCode()
        return result
    }

    companion object : Asn1Serializable<Asn1Sequence, X509Certificate> {
        override val leadingTags = setOf(Asn1Element.Tag.SEQUENCE)

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): X509Certificate = src.decodeRethrowing {
            val tbsCertificate = TbsCertificate.decodeFromTlv(next().asSequence())
            val signatureAlgorithm = SignatureAlgorithmIdentifier.decodeFromTlv(next().asSequence())
            val signatureValue = Asn1BitString.decodeFromTlv(next().asPrimitive())
            X509Certificate(tbsCertificate, signatureAlgorithm, signatureValue)
        }
    }
}
