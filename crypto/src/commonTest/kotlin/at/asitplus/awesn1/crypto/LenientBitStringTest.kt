package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.Sec1EcPublicKeyInfo.Companion.ec
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.awesn1.crypto.pki.X500Name
import at.asitplus.awesn1.crypto.pki.X500RelativeDistinguishedName
import at.asitplus.awesn1.crypto.pki.X509TbsCertificate
import at.asitplus.awesn1.serialization.DER
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlin.time.Instant

val LenientBitStringTest by matrixSuite {

    "malformed unique ID decodes and round trips" {
        val validDer = DER.encodeToByteArray(minimalTbsCertificate(issuerUniqueID = Asn1BitString.fromByteArray(byteArrayOf(0xe0.toByte()), 5)))
        val malformedDer = validDer.replaceFirst(
            byteArrayOf(0x81.toByte(), 0x02, 0x05, 0xE0.toByte()),
            byteArrayOf(0x81.toByte(), 0x02, 0x05, 0xE1.toByte()),
        )

        val decodedValid = DER.decodeFromByteArray<X509TbsCertificate>(validDer)
        val decodedInvalid = DER.decodeFromByteArray<X509TbsCertificate>(malformedDer)

        decodedValid shouldBe decodedInvalid
        decodedValid.hashCode() shouldBe decodedInvalid.hashCode()
        DER.encodeToByteArray(decodedInvalid) shouldBe malformedDer
        decodedValid.issuerUniqueID shouldBe decodedInvalid.issuerUniqueID
    }

    "absent unique ID remains null" {
        val decoded = DER.decodeFromByteArray<X509TbsCertificate>(DER.encodeToByteArray(minimalTbsCertificate()))

        decoded.issuerUniqueID shouldBe null
        decoded.subjectUniqueID shouldBe null
    }

    "valid unique IDs round-trip through semantic getters" {
        val issuer = Asn1BitString.fromBitSet(BitSet.fromString("101")).asGeneral()
        val subject = Asn1BitString.fromBitSet(BitSet.fromString("111000001")).asGeneral()
        val decoded = DER.decodeFromByteArray<X509TbsCertificate>(
            DER.encodeToByteArray(minimalTbsCertificate(issuerUniqueID = issuer, subjectUniqueID = subject))
        )

        decoded.issuerUniqueID shouldBe issuer
        decoded.subjectUniqueID shouldBe subject
    }
}

private fun minimalTbsCertificate(
    issuerUniqueID: Asn1BitString.General? = null,
    subjectUniqueID: Asn1BitString.General? = null,
) = X509TbsCertificate(
    serialNumber = Asn1Integer(1u),
    signatureAlgorithm = X509AlgorithmIdentifier(ObjectIdentifier("1.2.840.113549.1.1.11"), null),
    issuerName = X500Name(X500RelativeDistinguishedName(setOf(X500AttributeTypeAndValue.CommonName("issuer")))),
    validFrom = Asn1Time.SecondsCapped(Instant.fromEpochSeconds(1_700_000_000L)),
    validUntil = Asn1Time.SecondsCapped(Instant.fromEpochSeconds(1_700_086_400L)),
    subjectName = X500Name(X500RelativeDistinguishedName(setOf(X500AttributeTypeAndValue.CommonName("subject")))),
    subjectPublicKeyInfo = SubjectPublicKeyInfo.ec(
        curveOid = ObjectIdentifier("1.2.840.10045.3.1.7"),
        xBytes = ByteArray(64) { 0x1 },
        usePositiveY = true),
    issuerUniqueID = issuerUniqueID,
    subjectUniqueID = subjectUniqueID,
)

private fun ByteArray.replaceFirst(old: ByteArray, new: ByteArray): ByteArray {
    require(old.size == new.size)
    val index = indices.first { start ->
        start + old.size <= size && old.indices.all { this[start + it] == old[it] }
    }
    return copyOf().also { out ->
        new.copyInto(out, index)
    }
}
