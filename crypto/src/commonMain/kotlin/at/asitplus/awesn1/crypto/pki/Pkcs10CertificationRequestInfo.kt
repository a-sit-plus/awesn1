// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
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
 * [rawAttributes] is modelled as a generic collection to be able to hold malformed data too. Canonical sorting happens only on encode! Hence, the order of attributes may differ
 */
@Serializable
data class Pkcs10CertificationRequestInfo private constructor(
    val version: Version = Version.V1,
    val subjectName: X500Name,
    val publicKey: SubjectPublicKeyInfo,
    @Asn1Tag(tagNumber = 0u)
    val rawAttributes: Collection<Pkcs10CsrAttribute> = emptyList(),
) {

    constructor(
        version: Version = Version.V1,
        subjectName: X500Name,
        publicKey: SubjectPublicKeyInfo,
        attributes: Set<Pkcs10CsrAttribute> = emptySet(),
    ) : this(version, subjectName, publicKey, rawAttributes = attributes.toSet())


    /**
     * Returns this CertificationRequestInfo's attributes **iff* they are distinct by OID.
     *
     * @throws if duplicate OIDs are found
     */
    @OptIn(ExperimentalObjCRefinement::class)
    @Suppress("WRONG_ANNOTATION_TARGET_WITH_USE_SITE_TARGET")
    @get:Throws(IllegalArgumentException::class)
    @HiddenFromObjC
    @get:HiddenFromObjC
    val attributes: Set<Pkcs10CsrAttribute>
        get() = if (rawAttributes.distinctBy { it.oid }.size != rawAttributes.size)
            throw Asn1Exception("Multiple CSR attributes with the same OID found")
        else rawAttributes.toSet()


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

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Pkcs10CertificationRequestInfo) return false

        if (version != other.version) return false
        if (subjectName != other.subjectName) return false
        if (publicKey != other.publicKey) return false
        if (rawAttributes.containsAll(other.rawAttributes) && other.rawAttributes.containsAll(rawAttributes)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = version.hashCode()
        result = 31 * result + subjectName.hashCode()
        result = 31 * result + publicKey.hashCode()
        result = 31 * result + rawAttributes.toList().hashCode()
        return result
    }
}

