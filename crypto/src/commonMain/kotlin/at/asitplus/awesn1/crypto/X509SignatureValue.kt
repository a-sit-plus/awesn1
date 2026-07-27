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
 * As per [RFC5280](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1):
 * ```
 * signatureValue       BIT STRING
 * ```
 *
 * This type models `signatureValue`, represented as raw `BIT STRING` bytes.
 * Helper methods `decodeRS` / `fromRS` use ASN.1 `ECDSA-Sig-Value` from
 * [RFC5759](https://www.rfc-editor.org/rfc/rfc5759.html#section-4.2):
 * ```
 * ECDSA-Sig-Value ::= SEQUENCE {
 *   r  INTEGER,
 *   s  INTEGER
 * }
 * ```
 */
@JvmInline
@Serializable
value class X509SignatureValue(val rawBitString: Asn1BitString): WrappedEncodable<Asn1BitString> {
    init {
        if (rawBitString.numPaddingBits != 0.toByte()) {
            throw Asn1Exception("The signature value must not have padding bits")
        }
    }

    override val value: Asn1BitString get() = rawBitString

    constructor(rawBytes: ByteArray) : this(Asn1BitString(rawBytes))

    val rawBytes: ByteArray get() = rawBitString.bitCarryingBytes

    // runRethrowing: a malformed ECDSA-Sig-Value (fewer than two children, or non-positive integers) would
    // otherwise leak NoSuchElementException/ClassCastException instead of a catchable Asn1Exception.
    @Throws(Asn1Exception::class)
    fun decodeRS(): Pair<Asn1Integer.Positive, Asn1Integer.Positive> = runRethrowing {
        Asn1Element.parse(rawBytes).asSequence().decodeAs {
            next().asPrimitive().decodeToAsn1Integer() as Asn1Integer.Positive to
                next().asPrimitive().decodeToAsn1Integer() as Asn1Integer.Positive
        }
    }

    companion object {
        fun fromRS(r: Asn1Integer.Positive, s: Asn1Integer.Positive) =
            X509SignatureValue(Asn1.Sequence { +r; +s }.derEncoded)
    }
}

fun X509SignatureValue.decodeRsOrNull() = catchingUnwrapped { decodeRS() }.getOrNull()
