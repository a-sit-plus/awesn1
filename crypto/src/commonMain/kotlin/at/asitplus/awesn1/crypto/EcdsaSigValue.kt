// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Der
import at.asitplus.awesn1.serialization.decodeFromDer
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToByteArray

/**
 * ECDSA-Sig-Value as specified by
 * [RFC 5480, Appendix A](https://www.rfc-editor.org/rfc/rfc5480.html#page-18):
 *
 * ```
 * ECDSA-Sig-Value ::= SEQUENCE {
 *   r  INTEGER,
 *   s  INTEGER
 * }
 * ```
 */
@Serializable
data class EcdsaSigValue(val r: Asn1Integer, val s: Asn1Integer) {
    fun toX509SignatureValue(der: Der = DER) = X509SignatureValue(der.encodeToByteArray(this))
    companion object {
        fun X509SignatureValue.toEcdsaSigValue(der: Der = DER) = der.decodeFromDer<EcdsaSigValue>(rawBytes)
    }
}

