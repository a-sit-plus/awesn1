// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.decodeRethrowing
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.decodeToInt
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.awesn1.serialization.Asn1Serializable
import kotlinx.serialization.Serializable

@Serializable(with = Pkcs10CertificationRequestInfo.Companion::class)
open class Pkcs10CertificationRequestInfo(
    val version: Int = 0,
    val subjectName: List<RelativeDistinguishedName>,
    val publicKey: SubjectPublicKeyInfo,
    val attributes: List<Attribute> = listOf(),
) : at.asitplus.awesn1.Asn1Encodable<Asn1Sequence> {

    override fun encodeToTlv() = Asn1.Sequence {
        +Asn1.Int(version)
        +Asn1.Sequence { subjectName.forEach { +it } }
        +publicKey
        +Asn1.ExplicitlyTagged(0uL) { attributes.forEach { +it } }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Pkcs10CertificationRequestInfo) return false
        return version == other.version &&
            subjectName == other.subjectName &&
            publicKey == other.publicKey &&
            attributes == other.attributes
    }

    override fun hashCode(): Int {
        var result = version
        result = 31 * result + subjectName.hashCode()
        result = 31 * result + publicKey.hashCode()
        result = 31 * result + attributes.hashCode()
        return result
    }

    companion object : Asn1Serializable<Asn1Sequence, Pkcs10CertificationRequestInfo> {
        override val leadingTags = setOf(Asn1Element.Tag.SEQUENCE)

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): Pkcs10CertificationRequestInfo = src.decodeRethrowing {
            val version = next().asPrimitive().decodeToInt()
            val subject = next().asSequence().children.map { RelativeDistinguishedName.decodeFromTlv(it.asSet()) }
            val publicKey = SubjectPublicKeyInfo.decodeFromTlv(next().asSequence())
            val attributes = if (hasNext()) {
                next().asExplicitlyTagged().verifyTag(0uL).map { Attribute.decodeFromTlv(it.asSequence()) }
            } else {
                emptyList()
            }
            Pkcs10CertificationRequestInfo(version, subject, publicKey, attributes)
        }
    }
}
