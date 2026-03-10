// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1PrimitiveOctetString
import at.asitplus.awesn1.Asn1PemDecodable
import at.asitplus.awesn1.Asn1PemEncodable
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.decodeRethrowing
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.serialization.Asn1Serializable
import kotlinx.serialization.Serializable

@Serializable(with = EncryptedPrivateKeyInfo.Companion::class)
open class EncryptedPrivateKeyInfo(
    val encryptionAlgorithm: Asn1Sequence,
    val encryptedData: Asn1PrimitiveOctetString,
) : Asn1PemEncodable<Asn1Sequence> {

    override val pemLabel: String = "ENCRYPTED PRIVATE KEY"

    override fun encodeToTlv() = Asn1.Sequence {
        +encryptionAlgorithm
        +encryptedData
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is EncryptedPrivateKeyInfo) return false
        return encryptionAlgorithm == other.encryptionAlgorithm && encryptedData == other.encryptedData
    }

    override fun hashCode(): Int = 31 * encryptionAlgorithm.hashCode() + encryptedData.hashCode()

    companion object : Asn1PemDecodable<Asn1Sequence, EncryptedPrivateKeyInfo>, Asn1Serializable<Asn1Sequence, EncryptedPrivateKeyInfo> {
        override val leadingTags = setOf(Asn1Element.Tag.SEQUENCE)

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): EncryptedPrivateKeyInfo = src.decodeRethrowing {
            val algorithm = next().asSequence()
            val encryptedData = Asn1PrimitiveOctetString(next().asPrimitive().content)
            EncryptedPrivateKeyInfo(algorithm, encryptedData)
        }
    }
}
