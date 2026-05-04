// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1Integer
import kotlinx.serialization.Serializable

/**
 *
 * As per [RFC8017](https://www.rfc-editor.org/rfc/rfc8017.html#appendix-A.1.2):
 * ```
 * RSAPrivateKey ::= SEQUENCE {
 *   version           Version,
 *   modulus           INTEGER,
 *   publicExponent    INTEGER,
 *   privateExponent   INTEGER,
 *   prime1            INTEGER,
 *   prime2            INTEGER,
 *   exponent1         INTEGER,
 *   exponent2         INTEGER,
 *   coefficient       INTEGER,
 *   otherPrimeInfos   OtherPrimeInfos OPTIONAL
 * }
 * ```
 */
@Serializable
data class Pkcs1RsaPrivateKeyInfo(
    val version: Int,
    val modulus: Asn1Integer,
    val publicExponent: Asn1Integer,
    val privateExponent: Asn1Integer,
    val prime1: Asn1Integer,
    val prime2: Asn1Integer,
    val exponent1: Asn1Integer,
    val exponent2: Asn1Integer,
    val coefficient: Asn1Integer,
    val otherPrimeInfos: List<Pkcs1RsaOtherPrimeInfo>? = null,
)
