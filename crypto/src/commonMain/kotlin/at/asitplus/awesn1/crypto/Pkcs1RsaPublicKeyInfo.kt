// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.WithPemLabel
import at.asitplus.awesn1.PemLabelSpec
import kotlinx.serialization.Serializable

/**
 *
 * As per [RFC8017](https://www.rfc-editor.org/rfc/rfc8017.html#appendix-A.1.1):
 * ```
 * RSAPublicKey ::= SEQUENCE {
 *   modulus           INTEGER,
 *   publicExponent    INTEGER
 * }
 * ```
 */
@Serializable
data class Pkcs1RsaPublicKeyInfo(
    val modulus: Asn1Integer,
    val publicExponent: Asn1Integer,
) : WithPemLabel {
    override val pemLabel: String get() = PEM_LABEL

    companion object : PemLabelSpec<Pkcs1RsaPublicKeyInfo> {
        const val PEM_LABEL = "RSA PUBLIC KEY"
        override val canonicalPemLabel: String get() = PEM_LABEL
    }
}
