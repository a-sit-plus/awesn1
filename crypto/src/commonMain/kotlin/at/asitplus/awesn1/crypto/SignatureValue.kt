// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Encodable
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.BitSet
import at.asitplus.awesn1.catchingUnwrapped
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.decodeToAsn1Integer
import at.asitplus.awesn1.encoding.parse

typealias SignatureValue = Asn1BitString

/**
 * Decodes r,s signature components from a SEQUENCE nested inside a signature values' BIT_STRING bytes.
 * Throws if no such structure is present.
 */
@Throws(Asn1Exception::class)
fun SignatureValue.decodeRS() : Pair<Asn1Integer.Positive, Asn1Integer.Positive> {
    if(numPaddingBits !=0.toByte()) throw Asn1Exception("Signature is padded")
    return Asn1Element.parse(rawBytes).asSequence().decodeAs {
        next().asPrimitive().decodeToAsn1Integer() as Asn1Integer.Positive to next().asPrimitive().decodeToAsn1Integer() as Asn1Integer.Positive
    }
}

fun SignatureValue.decodeRsOrNull() = catchingUnwrapped { decodeRS() }.getOrNull()

fun SignatureValue(r: Asn1Integer.Positive, s: Asn1Integer.Positive): SignatureValue =
    Asn1BitString(Asn1.Sequence { +r;+s }.derEncoded)