package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1Time
import at.asitplus.awesn1.BitSet
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.awesn1.crypto.pki.X500RelativeDistinguishedName
import at.asitplus.awesn1.crypto.pki.X509TbsCertificate
import at.asitplus.awesn1.serialization.DER
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlin.time.Instant

val LenientBitStringTest by matrixSuite {

    "malformed unique ID decodes but strict getter throws lazily" {
        val validDer = DER.encodeToByteArray(minimalTbsCertificate(issuerUniqueID = BitSet.fromString("111").let(::Asn1BitString)))
        val malformedDer = validDer.replaceFirst(
            byteArrayOf(0x81.toByte(), 0x02, 0x05, 0xE0.toByte()),
            byteArrayOf(0x81.toByte(), 0x02, 0x05, 0xE1.toByte()),
        )

        val decoded = DER.decodeFromByteArray<X509TbsCertificate>(malformedDer)
        val decodedAgain = DER.decodeFromByteArray<X509TbsCertificate>(malformedDer)

        decoded shouldBe decodedAgain
        decoded.hashCode() shouldBe decodedAgain.hashCode()
        DER.encodeToByteArray(decoded) shouldBe malformedDer
        shouldThrow<Asn1Exception> {
            decoded.issuerUniqueID
        }.message shouldBe "Last 5 padding bits must be zeroed out. Last byte is: 11100001"
    }

    "absent unique ID remains null" {
        val decoded = DER.decodeFromByteArray<X509TbsCertificate>(DER.encodeToByteArray(minimalTbsCertificate()))

        decoded.issuerUniqueID shouldBe null
        decoded.subjectUniqueID shouldBe null
    }

    "valid unique IDs round-trip through semantic getters" {
        val issuer = Asn1BitString(BitSet.fromString("101"))
        val subject = Asn1BitString(BitSet.fromString("111000001"))
        val decoded = DER.decodeFromByteArray<X509TbsCertificate>(
            DER.encodeToByteArray(minimalTbsCertificate(issuerUniqueID = issuer, subjectUniqueID = subject))
        )

        decoded.issuerUniqueID shouldBe issuer
        decoded.subjectUniqueID shouldBe subject
    }
}

private fun minimalTbsCertificate(
    issuerUniqueID: Asn1BitString? = null,
    subjectUniqueID: Asn1BitString? = null,
) = X509TbsCertificate(
    serialNumber = Asn1Integer(1u),
    signatureAlgorithm = X509AlgorithmIdentifier(ObjectIdentifier("1.2.840.113549.1.1.11"), emptyList()),
    issuerName = listOf(X500RelativeDistinguishedName(setOf(X500AttributeTypeAndValue.CommonName("issuer")))),
    validFrom = Asn1Time.SecondsCapped(Instant.fromEpochSeconds(1_700_000_000L)),
    validUntil = Asn1Time.SecondsCapped(Instant.fromEpochSeconds(1_700_086_400L)),
    subjectName = listOf(X500RelativeDistinguishedName(setOf(X500AttributeTypeAndValue.CommonName("subject")))),
    subjectPublicKeyInfo = SubjectPublicKeyInfo.ec(ObjectIdentifier("1.2.840.10045.3.1.7"), ByteArray(65) { it.toByte() }),
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
