// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.awesn1.serialization.Asn1ConstructedBit
import at.asitplus.awesn1.serialization.Asn1Tag
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
    val version: Int = 0,
    val subjectName: List<RelativeDistinguishedName>,
    val publicKey: SubjectPublicKeyInfo,
    @Asn1Tag(tagNumber = 0u, constructed = Asn1ConstructedBit.CONSTRUCTED)
    val attributes: List<Attribute> = emptyList(),
)
