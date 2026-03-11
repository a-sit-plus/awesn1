// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.decodeRethrowing
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.decodeToAsn1Integer
import at.asitplus.awesn1.serialization.Asn1Serializable
import kotlinx.serialization.Serializable

@Serializable(with = EcdsaSignatureValue.Companion::class)
open class EcdsaSignatureValue(
    val r: Asn1Integer.Positive,
    val s: Asn1Integer.Positive,
) : SignatureValue<Asn1Sequence> {

    override fun encodeToTlv() = Asn1.Sequence {
        +r
        +s
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is EcdsaSignatureValue) return false
        return r == other.r && s == other.s
    }

    override fun hashCode(): Int = 31 * r.hashCode() + s.hashCode()

    companion object : Asn1Serializable<Asn1Sequence, EcdsaSignatureValue> {
        override val leadingTags = setOf(Asn1Element.Tag.SEQUENCE)

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): EcdsaSignatureValue = src.decodeRethrowing {
            val r = next().asPrimitive().decodeToAsn1Integer() as Asn1Integer.Positive
            val s = next().asPrimitive().decodeToAsn1Integer() as Asn1Integer.Positive
            EcdsaSignatureValue(r, s)
        }
    }
}
