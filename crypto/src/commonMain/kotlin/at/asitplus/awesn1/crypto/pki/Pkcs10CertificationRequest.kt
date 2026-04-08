// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1PemDecodable
import at.asitplus.awesn1.Asn1PemEncodable
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.decodeRethrowing
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.crypto.SignatureAlgorithmIdentifier
import at.asitplus.awesn1.crypto.SignatureValue
import at.asitplus.awesn1.serialization.Asn1Serializable
import kotlinx.serialization.Serializable

@Serializable(with = Pkcs10CertificationRequest.Companion::class)
open class Pkcs10CertificationRequest(
    val certificationRequestInfo: Pkcs10CertificationRequestInfo,
    val signatureAlgorithm: SignatureAlgorithmIdentifier,
    val signatureValue: SignatureValue,
) : Asn1PemEncodable<Asn1Sequence> {

    override val pemLabel get() = PEM_LABEL

    override fun encodeToTlv() = Asn1.Sequence {
        +certificationRequestInfo
        +signatureAlgorithm
        +Asn1.BitString(signatureValue.rawBytes)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Pkcs10CertificationRequest) return false
        return certificationRequestInfo == other.certificationRequestInfo &&
            signatureAlgorithm == other.signatureAlgorithm &&
            signatureValue == other.signatureValue
    }

    override fun hashCode(): Int {
        var result = certificationRequestInfo.hashCode()
        result = 31 * result + signatureAlgorithm.hashCode()
        result = 31 * result + signatureValue.hashCode()
        return result
    }

    companion object :
        Asn1Serializable<Asn1Sequence, Pkcs10CertificationRequest>,
        Asn1PemDecodable<Asn1Sequence, Pkcs10CertificationRequest>
    {
        override val leadingTags = setOf(Asn1Element.Tag.SEQUENCE)

        const val PEM_LABEL = "CERTIFICATE REQUEST"
        override val pemLabel get() = PEM_LABEL

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): Pkcs10CertificationRequest = src.decodeRethrowing {
            val info = Pkcs10CertificationRequestInfo.decodeFromTlv(next().asSequence())
            val signatureAlgorithm = SignatureAlgorithmIdentifier.decodeFromTlv(next().asSequence())
            val signatureValue = SignatureValue.decodeFromTlv(next().asPrimitive())
            Pkcs10CertificationRequest(info, signatureAlgorithm, signatureValue)
        }
    }
}
