// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.asAsn1BitString
import at.asitplus.awesn1.serialization.Asn1Serializable
import kotlinx.serialization.Serializable

@Serializable(with = BitStringSignatureValue.Companion::class)
open class BitStringSignatureValue(
    val bitString: Asn1BitString,
) : SignatureValue<Asn1Primitive> {

    override fun encodeToTlv() = Asn1.BitString(bitString.rawBytes)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is BitStringSignatureValue) return false
        return bitString == other.bitString
    }

    override fun hashCode(): Int = bitString.hashCode()

    companion object : Asn1Serializable<Asn1Primitive, BitStringSignatureValue> {
        override val leadingTags = setOf(Asn1Element.Tag.BIT_STRING)

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Primitive): BitStringSignatureValue =
            BitStringSignatureValue(src.asAsn1BitString())
    }
}
