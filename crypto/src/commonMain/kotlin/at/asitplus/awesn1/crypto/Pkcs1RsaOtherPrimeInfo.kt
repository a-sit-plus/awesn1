// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1Integer
import kotlinx.serialization.Serializable

/**
 *
 * As per [RFC8017](https://www.rfc-editor.org/rfc/rfc8017.html#appendix-A.1.2):
 * ```
 * OtherPrimeInfo ::= SEQUENCE {
 *   prime             INTEGER,
 *   exponent          INTEGER,
 *   coefficient       INTEGER
 * }
 * ```
 */
@Serializable
data class Pkcs1RsaOtherPrimeInfo(
    val prime: Asn1Integer.Positive,
    val exponent: Asn1Integer.Positive,
    val coefficient: Asn1Integer.Positive,
)
