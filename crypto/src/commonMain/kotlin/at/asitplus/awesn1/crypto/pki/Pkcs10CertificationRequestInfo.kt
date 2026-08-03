// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.awesn1.serialization.LenientSet
import at.asitplus.awesn1.serialization.Asn1Tag
import kotlinx.serialization.Serializable
import kotlin.experimental.ExperimentalObjCRefinement
import kotlin.native.HiddenFromObjC

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
 * Attributes { ATTRIBUTE:IOSet } ::= SET OF Attribute{{ IOSet }}
 *
 * CRIAttributes  ATTRIBUTE  ::= {
 * ... -- add any locally defined attributes here -- }
 *
 * Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
 *   type   ATTRIBUTE.&id({IOSet}),
 *   values SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{@type})
 * }
 * ```
 *
 * [rawAttributes] uses [LenientSet] to hold malformed data too. **DO NOT ASSUME ANY PARTICULAR ORDER OR CONCRETE COLLECTION TYPE!** Canonical sorting happens only on encode!
 * Hence, the order of attributes may differ post-encode.
 *
 * This class's [equals] and [hashCode] reflect this characteristic: Order of attributes is irrelevant for equality!
 */
@ConsistentCopyVisibility
@Serializable
data class Pkcs10CertificationRequestInfo private constructor(
    val version: Version = Version.V1,
    val subjectName: X500Name,
    val publicKey: SubjectPublicKeyInfo,
    @Asn1Tag(tagNumber = 0u)
    val rawAttributes: LenientSet<Pkcs10CsrAttribute> = LenientSet(),
) {

    constructor(
        version: Version = Version.V1,
        subjectName: X500Name,
        publicKey: SubjectPublicKeyInfo,
        attributes: Set<Pkcs10CsrAttribute> = emptySet(),
    ) : this(version, subjectName, publicKey, rawAttributes = LenientSet(attributes)) {
        require(attributes.distinctBy { it.oid }.size == attributes.size) {
            "Multiple CSR attributes with the same OID found"
        }
    }


    /**
     * Returns this CertificationRequestInfo's attributes **iff* they are distinct by OID.
     *
     * @throws Asn1Exception in case duplicate OIDs are found
     */
    @OptIn(ExperimentalObjCRefinement::class)
    @Suppress("WRONG_ANNOTATION_TARGET_WITH_USE_SITE_TARGET")
    @get:Throws(Asn1Exception::class)
    @HiddenFromObjC
    @get:HiddenFromObjC
    val attributes: Set<Pkcs10CsrAttribute>
        get() = rawAttributes.toValidatedSet().also {
            if (it.distinctBy { attribute -> attribute.oid }.size != it.size)
                throw Asn1Exception("Multiple CSR attributes with the same OID found")
        }


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
