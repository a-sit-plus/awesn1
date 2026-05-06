// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.awesn1.serialization.ExplicitlyTagged
import at.asitplus.awesn1.serialization.getValue
import at.asitplus.awesn1.serialization.orValue
import at.asitplus.awesn1.toInt
import kotlinx.serialization.Serializable

/**
 * RSASSA-PSS parameters as specified by
 * [RFC 4055, section 3.1](https://www.rfc-editor.org/rfc/rfc4055.html#section-3.1):
 *
 * ```
 * RSASSA-PSS-params ::= SEQUENCE {
 *   hashAlgorithm      [0] HashAlgorithm      DEFAULT sha1Identifier,
 *   maskGenAlgorithm   [1] MaskGenAlgorithm   DEFAULT mgf1SHA1Identifier,
 *   saltLength         [2] INTEGER            DEFAULT 20,
 *   trailerField       [3] TrailerField       DEFAULT trailerFieldBC
 * }
 * ```
 *
 * The encoded fields are optional because the ASN.1 type defines defaults. The `effective*` accessors expose the
 * RFC defaults without forcing callers to reject unsupported parameter combinations while parsing an outer
 * [X509AlgorithmIdentifier].
 */
@Serializable
data class RsaSsaPssParams(
    @Asn1Tag(tagNumber = 0u)
    val rawHashAlgorithm: ExplicitlyTagged<X509AlgorithmIdentifier>? = null,
    @Asn1Tag(tagNumber = 1u)
    val rawMaskGenAlgorithm: ExplicitlyTagged<X509AlgorithmIdentifier>? = null,
    @Asn1Tag(tagNumber = 2u)
    val rawSaltLength: ExplicitlyTagged<Asn1Integer>? = null,
    @Asn1Tag(tagNumber = 3u)
    val rawTrailerField: ExplicitlyTagged<Asn1Integer>? = null,
) {

    val hashAlgorithm: X509AlgorithmIdentifier? by rawHashAlgorithm

    val maskGenAlgorithm:X509AlgorithmIdentifier? by rawMaskGenAlgorithm

    val saltLength: Asn1Integer? by rawSaltLength

    val trailerField: Asn1Integer? by rawTrailerField

    val effectiveHashAlgorithm: X509AlgorithmIdentifier get() = hashAlgorithm ?: SHA1_IDENTIFIER

    val effectiveMaskGenAlgorithm: X509AlgorithmIdentifier get() = maskGenAlgorithm ?: MGF1_SHA1_IDENTIFIER

    /**
     * Getter may throw but we cannot annotate due to https://youtrack.jetbrains.com/issue/KT-63047/Throws-annotation-on-getter-leads-to-compile-time-error-for-iOS-target
     */
    val effectiveSaltLength: Int by lazy { saltLength?.toInt() ?: DEFAULT_SALT_LENGTH }

    /**
     * Getter may throw but we cannot annotate due to https://youtrack.jetbrains.com/issue/KT-63047/Throws-annotation-on-getter-leads-to-compile-time-error-for-iOS-target
     */
    val effectiveTrailerField: Int by lazy { trailerField?.toInt() ?: DEFAULT_TRAILER_FIELD }

    companion object {
        val RSA_SSA_PSS_OID = ObjectIdentifier("1.2.840.113549.1.1.10")
        val MGF1_OID = ObjectIdentifier("1.2.840.113549.1.1.8")
        val SHA1_OID = ObjectIdentifier("1.3.14.3.2.26")

        const val DEFAULT_SALT_LENGTH = 20
        const val DEFAULT_TRAILER_FIELD = 1

        val SHA1_IDENTIFIER = X509AlgorithmIdentifier(SHA1_OID, Asn1.Null())
        val MGF1_SHA1_IDENTIFIER = X509AlgorithmIdentifier(MGF1_OID, SHA1_IDENTIFIER.element)
    }
}
