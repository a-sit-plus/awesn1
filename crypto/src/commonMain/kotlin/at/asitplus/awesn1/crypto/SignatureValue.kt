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

@JvmInline
@Serializable(with = SignatureValue.Companion::class)
value class SignatureValue
@Throws(Asn1Exception::class)
private constructor(val rawBitString: Asn1BitString) : Asn1Encodable<Asn1Primitive> {

    init {
        if (rawBitString.numPaddingBits != 0.toByte()) throw Asn1Exception("The signature value must have padding bits")
    }

    constructor(rawBytes: ByteArray) : this(Asn1BitString(rawBytes))

    val rawBytes: ByteArray get() = rawBitString.rawBytes

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

    override fun encodeToTlv(): Asn1Primitive = rawBitString.encodeToTlv()

    companion object : Asn1Serializable<Asn1Primitive, SignatureValue> {
        override val leadingTags = Asn1BitString.leadingTags
        override fun doDecode(src: Asn1Primitive): SignatureValue {
            return SignatureValue(src.asAsn1BitString())
        }

        operator fun invoke(rawBitString: Asn1BitString) : SignatureValue = SignatureValue(rawBitString)
        /**
         * Constructs a Signature value from [r] and [s] coordinates (as used by ECDSA, and DSA, for example)
         */
        fun fromRS(r: Asn1Integer.Positive, s: Asn1Integer.Positive) =
            SignatureValue(Asn1.Sequence { +r; +s }.derEncoded)

    }
}


fun SignatureValue.decodeRsOrNull() = catchingUnwrapped { decodeRS() }.getOrNull()