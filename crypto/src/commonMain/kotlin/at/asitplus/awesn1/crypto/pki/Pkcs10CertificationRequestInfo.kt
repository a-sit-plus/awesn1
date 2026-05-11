// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.awesn1.crypto.Versioned
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.awesn1.toInt
import kotlinx.serialization.Serializable

/**
 *
 * As per [RFC2986](https://www.rfc-editor.org/rfc/rfc2986.html#section-4):
 * ```
 * CertificationRequestInfo ::= SEQUENCE {
 *   version       INTEGER { v1(0) } (v1,...),
 *   subject       Name,
 *   subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
 *   attributes    [0] Attributes{{ CRIAttributes }}
 * }
 * ```
 */
@Serializable
data class Pkcs10CertificationRequestInfo(
    override val rawVersion: Asn1Integer = Asn1Integer.ZERO,
    val subjectName: List<X500RelativeDistinguishedName>,
    val publicKey: SubjectPublicKeyInfo,
    @Asn1Tag(tagNumber = 0u)
    val attributes: List<Attribute> = emptyList(),
) : Versioned {
    constructor(
        version: Int = 1,
        subjectName: List<X500RelativeDistinguishedName>,
        publicKey: SubjectPublicKeyInfo,
        attributes: List<Attribute> = emptyList(),
    ) : this(Asn1Integer(version - 1), subjectName, publicKey, attributes)

    /**
     *
     * [rawVersion] reopresents the encoded integer, (semantic) [version] denotes the
     * version commonly referred to as the version of a CSR
     *
     * | RAW Version | (Semantic) Version |
     * |:-----------:|:----------------:|
     * | 0           | 1                |
     * The integer must fit the valid Int value range (within [Int.MIN_VALUE]..[Int.MAX_VALUE]), otherwise a [NumberFormatException] will be thrown.
     *
     * Getter may throw but we cannot annotate due to https://youtrack.jetbrains.com/issue/KT-63047/Throws-annotation-on-getter-leads-to-compile-time-error-for-iOS-target
     */
    override val version: Int by lazy { rawVersion.toInt() + 1 }

}
