// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.Asn1Encodable
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.decodeRethrowing
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.asAsn1BitString
import at.asitplus.awesn1.encoding.decodeToInt
import at.asitplus.awesn1.serialization.Asn1Serializable
import kotlinx.serialization.Serializable

@Serializable(with = EcPrivateKeyInfo.Companion::class)
open class EcPrivateKeyInfo(
    val version: Int,
    val privateKey: ByteArray,
    val parameters: ObjectIdentifier? = null,
    val publicKey: Asn1BitString? = null,
) : Asn1Encodable<Asn1Sequence> {

    override fun encodeToTlv() = Asn1.Sequence {
        +Asn1.Int(version)
        +Asn1.OctetString(privateKey)
        parameters?.let { +Asn1.ExplicitlyTagged(0uL) { +it } }
        publicKey?.let { +Asn1.ExplicitlyTagged(1uL) { +it } }
    }

    override fun equals(other: Any?): Boolean =
        other is EcPrivateKeyInfo &&
            version == other.version &&
            privateKey.contentEquals(other.privateKey) &&
            parameters == other.parameters &&
            publicKey == other.publicKey

    override fun hashCode(): Int {
        var result = version
        result = 31 * result + privateKey.contentHashCode()
        result = 31 * result + (parameters?.hashCode() ?: 0)
        result = 31 * result + (publicKey?.hashCode() ?: 0)
        return result
    }

    companion object : Asn1Serializable<Asn1Sequence, EcPrivateKeyInfo> {
        override val leadingTags = setOf(Asn1Element.Tag.SEQUENCE)

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): EcPrivateKeyInfo = src.decodeRethrowing {
            val version = next().asPrimitive().decodeToInt()
            val privateKey = next().asOctetString().content

            var parameters: ObjectIdentifier? = null
            var publicKey: Asn1BitString? = null
            while (hasNext()) {
                val field = next().asExplicitlyTagged()
                when (field.tag.tagValue) {
                    0uL -> {
                        require(parameters == null) { "Duplicate EC curve field in EC PrivateKey" }
                        require(publicKey == null) { "Field order violation in EC PrivateKey" }
                        require(field.children.size == 1) { "Invalid EC curve field in EC PrivateKey" }
                        parameters = ObjectIdentifier.decodeFromTlv(field.children.first().asPrimitive())
                    }

                    1uL -> {
                        require(publicKey == null) { "Duplicate public key field in EC PrivateKey" }
                        require(field.children.size == 1) { "Invalid public key field in EC PrivateKey" }
                        publicKey = field.children.first().asPrimitive().asAsn1BitString()
                    }

                    else -> throw Asn1Exception("Unknown optional field with tag ${field.tag.tagValue} in EC PrivateKey")
                }
            }

            EcPrivateKeyInfo(version, privateKey, parameters, publicKey)
        }
    }
}
