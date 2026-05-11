// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.toInt
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
    /**
     * corresponds verbatim to [RFC8017](https://www.rfc-editor.org/rfc/rfc8017.html#appendix-A.1.2):
     *  version is the version number, for compatibility with future
     *       revisions of this document.  It SHALL be 0 for this version of the
     *       document, unless multi-prime is used; in which case, it SHALL be
     *       1.
     *
     *             Version ::= INTEGER { two-prime(0), multi(1) }
     *                (CONSTRAINED BY
     *                {-- version must be multi if otherPrimeInfos present --})
     */
    override val rawVersion: Asn1Integer,
    val modulus: Asn1Integer.Positive,
    val publicExponent: Asn1Integer.Positive,
    val privateExponent: Asn1Integer.Positive,
    val prime1: Asn1Integer.Positive,
    val prime2: Asn1Integer.Positive,
    val exponent1: Asn1Integer.Positive,
    val exponent2: Asn1Integer.Positive,
    val coefficient: Asn1Integer.Positive,
    val otherPrimeInfos: List<Pkcs1RsaOtherPrimeInfo>? = null,
) : Versioned {
    /**
     *
     * [rawVersion] reopresents the encoded integer, (semantic) [version] denotes the
     * version commonly referred to as the version of a private key
     * The integer must fit the valid Int value range (within [Int.MIN_VALUE]..[Int.MAX_VALUE]), otherwise a [NumberFormatException] will be thrown.
     *
     * Getter may throw but we cannot annotate due to https://youtrack.jetbrains.com/issue/KT-63047/Throws-annotation-on-getter-leads-to-compile-time-error-for-iOS-target
     */
    override val version: Int by lazy { rawVersion.toInt() }
}
