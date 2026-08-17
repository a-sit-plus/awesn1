// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.catchingUnwrapped
import at.asitplus.awesn1.runRethrowing
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.WrappedEncodable
import at.asitplus.awesn1.encoding.decodeToAsn1Integer
import at.asitplus.awesn1.encoding.parse
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

/**
 *
 * This type models signatureValue as per [RFC5280](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1):
 * ```
 * signatureValue       BIT STRING
 * ```
 *
 * As a transparent [WrappedEncodable], a signature value can be added directly to an ASN.1 builder with unary `+`.
 */
@JvmInline
@Serializable
value class X509SignatureValue(val rawBitString: Asn1BitString): WrappedEncodable<Asn1BitString> {

    override val value: Asn1BitString get() = rawBitString

    constructor(rawBytes: ByteArray) : this(Asn1BitString(rawBytes))

    val rawBytes: ByteArray get() = rawBitString.also {
        if (it.numPaddingBits != 0.toByte())
            throw Asn1Exception("The signature value must not have padding bits")
    }.bitCarryingBytes
}
