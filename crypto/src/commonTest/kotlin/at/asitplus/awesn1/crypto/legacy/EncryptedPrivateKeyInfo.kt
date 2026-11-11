// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.legacy

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.serialization.Asn1Serializable
import at.asitplus.awesn1.serialization.PemDeserializable
import at.asitplus.awesn1.serialization.WithPemLabel
import kotlinx.serialization.Serializable

@Serializable(with = EncryptedPrivateKeyInfo.Companion::class)
open class EncryptedPrivateKeyInfo(
    val encryptionAlgorithm: Asn1Sequence,
    val encryptedData: Asn1OctetString,
) : Asn1Encodable<Asn1Sequence>, WithPemLabel {

    override val pemLabel get() = PEM_LABEL

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

    companion object : PemDeserializable<EncryptedPrivateKeyInfo>, Asn1Serializable<Asn1Sequence, EncryptedPrivateKeyInfo> {
        const val PEM_LABEL = "ENCRYPTED PRIVATE KEY"
        override val canonicalPemLabel: String get() = PEM_LABEL
        override val leadingTags = setOf(Asn1Element.Tag.SEQUENCE)

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): EncryptedPrivateKeyInfo = src.decodeRethrowing {
            val algorithm = next().asSequence()
            val encryptedData = Asn1OctetString(next().asPrimitive().content)
            EncryptedPrivateKeyInfo(algorithm, encryptedData)
        }
    }
}
