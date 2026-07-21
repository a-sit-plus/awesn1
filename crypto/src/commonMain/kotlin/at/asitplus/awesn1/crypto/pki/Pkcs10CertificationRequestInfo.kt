// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.TagClass
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
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
 *
 * Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
 *   type   ATTRIBUTE.&id({IOSet}),
 *   values SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{@type})
 * }
 *
 * ```
 */
@Serializable
data class Pkcs10CertificationRequestInfo(
    val version: Version = Version.V1,
    val subjectName: X500Name,
    val publicKey: SubjectPublicKeyInfo,
    @Asn1Tag(tagNumber = 0u)
    val attributes: List<Pkcs10CsrAttribute> = emptyList(),
) {

    /**
     * Legal CSR versions. As per [RFC2986](https://www.rfc-editor.org/rfc/rfc2986.html#section-4), only V1 is defined.
     *
     * | Encoded Version | Semantic Version |
     * |:---------------:|:----------------:|
     * | 0               | V1                |
     */
    @Asn1Tag(tagNumber = 0x02uL, tagClass = Asn1Tag.Class.UNIVERSAL)
    enum class Version {
        V1
    }
}
