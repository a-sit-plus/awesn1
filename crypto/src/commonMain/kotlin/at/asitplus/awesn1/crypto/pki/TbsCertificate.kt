// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1ExplicitlyTagged
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.decodeRethrowing
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.decodeToInt
import at.asitplus.awesn1.Asn1Time
import at.asitplus.awesn1.crypto.SignatureAlgorithmIdentifier
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.awesn1.serialization.Asn1Serializable
import kotlinx.serialization.Serializable

@Serializable(with = TbsCertificate.Companion::class)
open class TbsCertificate(
    val version: Int? = 2,
    val serialNumber: ByteArray,
    val signatureAlgorithm: SignatureAlgorithmIdentifier,
    val issuerName: List<RelativeDistinguishedName>,
    val validFrom: Asn1Time,
    val validUntil: Asn1Time,
    val subjectName: List<RelativeDistinguishedName>,
    val subjectPublicKeyInfo: SubjectPublicKeyInfo,
    val issuerUniqueID: Asn1BitString? = null,
    val subjectUniqueID: Asn1BitString? = null,
    val extensions: List<X509CertificateExtension>? = null,
) : at.asitplus.awesn1.Asn1Encodable<Asn1Sequence> {

    override fun encodeToTlv() = Asn1.Sequence {
        version?.let { +Asn1.ExplicitlyTagged(0uL) { +Asn1.Int(it) } }
        +at.asitplus.awesn1.Asn1Primitive(at.asitplus.awesn1.Asn1Element.Tag.INT, serialNumber)
        +signatureAlgorithm
        +Asn1.Sequence { issuerName.forEach { +it } }
        +Asn1.Sequence {
            +validFrom
            +validUntil
        }
        +Asn1.Sequence { subjectName.forEach { +it } }
        +subjectPublicKeyInfo
        issuerUniqueID?.let { +(it withImplicitTag 1uL) }
        subjectUniqueID?.let { +(it withImplicitTag 2uL) }
        extensions?.takeIf { it.isNotEmpty() }?.let { ext ->
            +Asn1.ExplicitlyTagged(3uL) {
                +Asn1.Sequence { ext.forEach { +it } }
            }
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is TbsCertificate) return false
        return version == other.version &&
            serialNumber.contentEquals(other.serialNumber) &&
            signatureAlgorithm == other.signatureAlgorithm &&
            issuerName == other.issuerName &&
            validFrom == other.validFrom &&
            validUntil == other.validUntil &&
            subjectName == other.subjectName &&
            subjectPublicKeyInfo == other.subjectPublicKeyInfo &&
            issuerUniqueID == other.issuerUniqueID &&
            subjectUniqueID == other.subjectUniqueID &&
            extensions == other.extensions
    }

    override fun hashCode(): Int {
        var result = version ?: 0
        result = 31 * result + serialNumber.contentHashCode()
        result = 31 * result + signatureAlgorithm.hashCode()
        result = 31 * result + issuerName.hashCode()
        result = 31 * result + validFrom.hashCode()
        result = 31 * result + validUntil.hashCode()
        result = 31 * result + subjectName.hashCode()
        result = 31 * result + subjectPublicKeyInfo.hashCode()
        result = 31 * result + (issuerUniqueID?.hashCode() ?: 0)
        result = 31 * result + (subjectUniqueID?.hashCode() ?: 0)
        result = 31 * result + (extensions?.hashCode() ?: 0)
        return result
    }

    companion object : Asn1Serializable<Asn1Sequence, TbsCertificate> {
        override val leadingTags = setOf(Asn1Element.Tag.SEQUENCE)

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): TbsCertificate = src.decodeRethrowing {
            val version = peek().let {
                if (it is Asn1ExplicitlyTagged) {
                    it.verifyTag(0uL).single().asPrimitive().decodeToInt().also { next() }
                } else null
            }
            val serialNumberElement = next().asPrimitive()
            if (serialNumberElement.tag != Asn1Element.Tag.INT) {
                throw at.asitplus.awesn1.Asn1TagMismatchException(Asn1Element.Tag.INT, serialNumberElement.tag)
            }
            val serialNumber = serialNumberElement.content
            val signatureAlgorithm = SignatureAlgorithmIdentifier.decodeFromTlv(next().asSequence())
            val issuerNames = next().asSequence().children.map { RelativeDistinguishedName.decodeFromTlv(it.asSet()) }
            val validity = next().asSequence().decodeRethrowing {
                Asn1Time.decodeFromTlv(next().asPrimitive()) to Asn1Time.decodeFromTlv(next().asPrimitive())
            }
            val subjectNames = next().asSequence().children.map { RelativeDistinguishedName.decodeFromTlv(it.asSet()) }
            val publicKey = SubjectPublicKeyInfo.decodeFromTlv(next().asSequence())
            val issuerUniqueID = peek()?.let { if (it.tag == Asn1.ImplicitTag(1uL)) Asn1BitString.decodeFromTlv(next().asPrimitive(), Asn1.ImplicitTag(1uL)) else null }
            val subjectUniqueID = peek()?.let { if (it.tag == Asn1.ImplicitTag(2uL)) Asn1BitString.decodeFromTlv(next().asPrimitive(), Asn1.ImplicitTag(2uL)) else null }
            val extensions = if (hasNext()) {
                next().asExplicitlyTagged().verifyTag(3uL).single().asSequence().children.map {
                    X509CertificateExtension.decodeFromTlv(it.asSequence())
                }
            } else null

            TbsCertificate(
                version = version,
                serialNumber = serialNumber,
                signatureAlgorithm = signatureAlgorithm,
                issuerName = issuerNames,
                validFrom = validity.first,
                validUntil = validity.second,
                subjectName = subjectNames,
                subjectPublicKeyInfo = publicKey,
                issuerUniqueID = issuerUniqueID,
                subjectUniqueID = subjectUniqueID,
                extensions = extensions,
            )
        }
    }
}
