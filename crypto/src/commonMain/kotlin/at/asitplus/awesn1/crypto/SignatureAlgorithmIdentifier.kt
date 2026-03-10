// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.Identifiable
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.decodeRethrowing
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.readOid
import at.asitplus.awesn1.serialization.Asn1Serializable
import kotlinx.serialization.Serializable

@Serializable(with = SignatureAlgorithmIdentifier.Companion::class)
open class SignatureAlgorithmIdentifier(
    override val oid: ObjectIdentifier,
    open val parameters: List<Asn1Element> = emptyList(),
) : Identifiable, at.asitplus.awesn1.Asn1Encodable<Asn1Sequence> {

    override fun encodeToTlv() = Asn1.Sequence {
        +oid
        parameters.forEach { +it }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SignatureAlgorithmIdentifier) return false
        return oid == other.oid && parameters == other.parameters
    }

    override fun hashCode(): Int = 31 * oid.hashCode() + parameters.hashCode()

    override fun toString(): String = "SignatureAlgorithmIdentifier($oid)"

    companion object : Asn1Serializable<Asn1Sequence, SignatureAlgorithmIdentifier> {
        override val leadingTags = setOf(Asn1Element.Tag.SEQUENCE)

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): SignatureAlgorithmIdentifier = src.decodeRethrowing {
            val oid = next().asPrimitive().readOid()
            val params = buildList {
                while (hasNext()) {
                    add(next())
                }
            }
            SignatureAlgorithmIdentifier(oid, params)
        }
    }
}
