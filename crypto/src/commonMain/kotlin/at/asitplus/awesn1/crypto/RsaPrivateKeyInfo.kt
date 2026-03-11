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
import at.asitplus.awesn1.encoding.decodeToInt
import at.asitplus.awesn1.serialization.Asn1Serializable
import kotlinx.serialization.Serializable

@Serializable(with = RsaPrivateKeyInfo.Companion::class)
open class RsaPrivateKeyInfo(
    val version: Int,
    val modulus: Asn1Integer,
    val publicExponent: Asn1Integer,
    val privateExponent: Asn1Integer,
    val prime1: Asn1Integer,
    val prime2: Asn1Integer,
    val exponent1: Asn1Integer,
    val exponent2: Asn1Integer,
    val coefficient: Asn1Integer,
    val otherPrimeInfos: List<RsaOtherPrimeInfo>? = null,
) : Asn1Encodable<Asn1Sequence> {

    override fun encodeToTlv() = Asn1.Sequence {
        +Asn1.Int(version)
        +modulus
        +publicExponent
        +privateExponent
        +prime1
        +prime2
        +exponent1
        +exponent2
        +coefficient
        otherPrimeInfos?.let { infos ->
            +Asn1.Sequence {
                infos.forEach { +it }
            }
        }
    }

    override fun equals(other: Any?): Boolean =
        other is RsaPrivateKeyInfo &&
            version == other.version &&
            modulus == other.modulus &&
            publicExponent == other.publicExponent &&
            privateExponent == other.privateExponent &&
            prime1 == other.prime1 &&
            prime2 == other.prime2 &&
            exponent1 == other.exponent1 &&
            exponent2 == other.exponent2 &&
            coefficient == other.coefficient &&
            otherPrimeInfos == other.otherPrimeInfos

    override fun hashCode(): Int {
        var result = version
        result = 31 * result + modulus.hashCode()
        result = 31 * result + publicExponent.hashCode()
        result = 31 * result + privateExponent.hashCode()
        result = 31 * result + prime1.hashCode()
        result = 31 * result + prime2.hashCode()
        result = 31 * result + exponent1.hashCode()
        result = 31 * result + exponent2.hashCode()
        result = 31 * result + coefficient.hashCode()
        result = 31 * result + (otherPrimeInfos?.hashCode() ?: 0)
        return result
    }

    companion object : Asn1Serializable<Asn1Sequence, RsaPrivateKeyInfo> {
        override val leadingTags = setOf(Asn1Element.Tag.SEQUENCE)

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): RsaPrivateKeyInfo = src.decodeRethrowing {
            val version = next().asPrimitive().decodeToInt()
            RsaPrivateKeyInfo(
                version = version,
                modulus = next().asPrimitive().decodeToAsn1Integer(),
                publicExponent = next().asPrimitive().decodeToAsn1Integer(),
                privateExponent = next().asPrimitive().decodeToAsn1Integer(),
                prime1 = next().asPrimitive().decodeToAsn1Integer(),
                prime2 = next().asPrimitive().decodeToAsn1Integer(),
                exponent1 = next().asPrimitive().decodeToAsn1Integer(),
                exponent2 = next().asPrimitive().decodeToAsn1Integer(),
                coefficient = next().asPrimitive().decodeToAsn1Integer(),
                otherPrimeInfos = if (hasNext()) {
                    next().asSequence().children.map { RsaOtherPrimeInfo.decodeFromTlv(it.asSequence()) }
                } else {
                    null
                }
            )
        }
    }
}
