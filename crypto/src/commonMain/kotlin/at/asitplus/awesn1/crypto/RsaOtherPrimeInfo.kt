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

@Serializable(with = RsaOtherPrimeInfo.Companion::class)
open class RsaOtherPrimeInfo(
    val prime: Asn1Integer,
    val exponent: Asn1Integer,
    val coefficient: Asn1Integer,
) : Asn1Encodable<Asn1Sequence> {

    override fun encodeToTlv() = Asn1.Sequence {
        +prime
        +exponent
        +coefficient
    }

    override fun equals(other: Any?): Boolean =
        other is RsaOtherPrimeInfo &&
            prime == other.prime &&
            exponent == other.exponent &&
            coefficient == other.coefficient

    override fun hashCode(): Int {
        var result = prime.hashCode()
        result = 31 * result + exponent.hashCode()
        result = 31 * result + coefficient.hashCode()
        return result
    }

    companion object : Asn1Serializable<Asn1Sequence, RsaOtherPrimeInfo> {
        override val leadingTags = setOf(Asn1Element.Tag.SEQUENCE)

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): RsaOtherPrimeInfo = src.decodeRethrowing {
            RsaOtherPrimeInfo(
                prime = next().asPrimitive().decodeToAsn1Integer(),
                exponent = next().asPrimitive().decodeToAsn1Integer(),
                coefficient = next().asPrimitive().decodeToAsn1Integer(),
            )
        }
    }
}
