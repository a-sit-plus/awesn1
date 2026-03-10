// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1Encodable
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.decodeRethrowing
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.decodeToAsn1Integer
import at.asitplus.awesn1.serialization.Asn1Serializable
import kotlinx.serialization.Serializable

@Serializable(with = RsaPublicKey.Companion::class)
open class RsaPublicKey(
    val modulus: Asn1Integer.Positive,
    val publicExponent: Asn1Integer.Positive,
) : Asn1Encodable<Asn1Sequence> {

    override fun encodeToTlv() = Asn1.Sequence {
        +modulus
        +publicExponent
    }

    override fun equals(other: Any?): Boolean =
        other is RsaPublicKey &&
            modulus == other.modulus &&
            publicExponent == other.publicExponent

    override fun hashCode(): Int = 31 * modulus.hashCode() + publicExponent.hashCode()

    companion object : Asn1Serializable<Asn1Sequence, RsaPublicKey> {
        override val leadingTags = setOf(Asn1Element.Tag.SEQUENCE)

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): RsaPublicKey = src.decodeRethrowing {
            RsaPublicKey(
                modulus = next().asPrimitive().decodeToAsn1Integer() as Asn1Integer.Positive,
                publicExponent = next().asPrimitive().decodeToAsn1Integer() as Asn1Integer.Positive,
            )
        }
    }
}
