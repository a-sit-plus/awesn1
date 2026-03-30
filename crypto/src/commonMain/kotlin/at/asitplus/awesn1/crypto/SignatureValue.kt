// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.asAsn1BitString
import at.asitplus.awesn1.encoding.decodeToAsn1Integer
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.serialization.Asn1Serializable
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable(with = SignatureValue.Companion::class)
class SignatureValue(val rawBytes: ByteArray) : Asn1Encodable<Asn1Primitive> {

    /**
     * Constructs a Signature value from [r] and [s] coordinates (as used by ECDSA, and DSA, for example)
     */
    constructor(r: Asn1Integer.Positive, s: Asn1Integer.Positive) : this(Asn1.Sequence { +r; +s }.derEncoded)

    /**
     * Decodes r,s signature components from a SEQUENCE nested inside a signature values' BIT_STRING bytes.
     * Throws if no such structure is present.
     */
    @Throws(Asn1Exception::class)
    fun decodeRS(): Pair<Asn1Integer.Positive, Asn1Integer.Positive> {
        return Asn1Element.parse(rawBytes).asSequence().decodeAs {
            next().asPrimitive().decodeToAsn1Integer() as Asn1Integer.Positive to next().asPrimitive()
                .decodeToAsn1Integer() as Asn1Integer.Positive
        }
    }

    override fun encodeToTlv(): Asn1Primitive = Asn1BitString(rawBytes).encodeToTlv()
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SignatureValue) return false

        if (!rawBytes.contentEquals(other.rawBytes)) return false

        return true
    }

    override fun hashCode(): Int {
        return rawBytes.contentHashCode()
    }

    companion object : Asn1Serializable<Asn1Primitive, SignatureValue> {
        override val leadingTags = Asn1BitString.leadingTags
        override fun doDecode(src: Asn1Primitive): SignatureValue {
            var bitString = src.asAsn1BitString()
            if (bitString.numPaddingBits != 0.toByte()) throw Asn1Exception("Padding bits found in signature")
            return SignatureValue(bitString.rawBytes)
        }
    }
}


fun SignatureValue.decodeRsOrNull() = catchingUnwrapped { decodeRS() }.getOrNull()