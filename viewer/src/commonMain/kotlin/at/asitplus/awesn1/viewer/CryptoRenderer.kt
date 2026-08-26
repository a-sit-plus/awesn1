// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.viewer

import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.EncryptedPrivateKeyInfo
import at.asitplus.awesn1.crypto.Pkcs1RsaPrivateKeyInfo
import at.asitplus.awesn1.crypto.Pkcs1RsaPublicKeyInfo
import at.asitplus.awesn1.crypto.Pkcs8PrivateKeyInfo
import at.asitplus.awesn1.crypto.Sec1EcPrivateKeyInfo
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequest
import at.asitplus.awesn1.crypto.pki.X500Name
import at.asitplus.awesn1.crypto.pki.X509Certificate
import at.asitplus.awesn1.crypto.pki.X509GeneralNames
import at.asitplus.awesn1.encoding.decodeToStringOrNull
import at.asitplus.awesn1.serialization.DER
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

private val JSON = Json { prettyPrint = true }

@OptIn(ExperimentalSerializationApi::class)
fun renderCryptoTypes(bytes: ByteArray): String = buildList {
    runCatching { DER.decodeFromByteArray(X509Certificate.serializer(), bytes) }.getOrNull()?.let {
        add(renderCertificate(it))
    }
    addDecoded("PKCS#10 certification request", Pkcs10CertificationRequest.serializer(), bytes)
    addDecoded("PKCS#8 private key", Pkcs8PrivateKeyInfo.serializer(), bytes)
    addDecoded("Encrypted private key", EncryptedPrivateKeyInfo.serializer(), bytes)
    addDecoded("PKCS#1 RSA private key", Pkcs1RsaPrivateKeyInfo.serializer(), bytes)
    addDecoded("SEC 1 EC private key", Sec1EcPrivateKeyInfo.serializer(), bytes)
    addDecoded("Subject public key info", SubjectPublicKeyInfo.serializer(), bytes)
    addDecoded("PKCS#1 RSA public key", Pkcs1RsaPublicKeyInfo.serializer(), bytes)
}.joinToString("\n\n")

private fun renderCertificate(certificate: X509Certificate): String = buildString {
    val tbs = certificate.tbsCertificate
    appendLine("X.509 certificate")
    appendLine("  Version: ${tbs.version}")
    appendLine("  Serial number: ${tbs.serialNumber.toHexString()}")
    appendLine("  Signature algorithm: ${certificate.signatureAlgorithm.oid.displayName()}")
    appendLine("  Issuer: ${tbs.issuerName.displayName()}")
    appendLine("  Valid from: ${tbs.validity.validFrom}")
    appendLine("  Valid until: ${tbs.validity.validUntil}")
    appendLine("  Subject: ${tbs.subjectName.displayName()}")
    appendLine("  Public-key algorithm: ${tbs.subjectPublicKeyInfo.algorithmOid.displayName()}")
    appendLine("  Public-key bits: ${tbs.subjectPublicKeyInfo.subjectPublicKey.bitCarryingBytes.size * 8 - tbs.subjectPublicKeyInfo.subjectPublicKey.numPaddingBits}")
    with(X509GeneralNames) {
        runCatching { certificate.findSubjectAltNames() }.getOrNull()?.let { names ->
            val values = names.dnsNames + names.rfc822Names + names.uris
            if (values.isNotEmpty()) appendLine("  Subject alternative names: ${values.joinToString()}")
        }
    }
    tbs.extensions?.takeIf { it.isNotEmpty() }?.let { extensions ->
        appendLine("  Extensions:")
        extensions.forEach {
            appendLine("    ${it.oid.displayName()}${if (it.critical) " [critical]" else ""} (${it.value.size} bytes)")
        }
    }
    append("  Signature bytes: ${certificate.signatureValue.rawBytes.size}")
}

private fun X500Name.displayName(): String = joinToString(", ") { rdn ->
    rdn.attrsAndValues.joinToString(" + ") { attribute ->
        val value = (attribute.value as? Asn1Primitive)?.decodeToStringOrNull() ?: attribute.value.toString()
        "${attribute.oid.displayName()}=$value"
    }
}

private fun ObjectIdentifier.displayName(): String =
    KnownOIDs[this]?.let { "$it ($this)" } ?: toString()

@OptIn(ExperimentalSerializationApi::class)
private fun <T> MutableList<String>.addDecoded(name: String, serializer: KSerializer<T>, bytes: ByteArray) {
    runCatching { DER.decodeFromByteArray(serializer, bytes) }.getOrNull()?.let {
        add("$name\n${JSON.encodeToString(serializer, it)}")
    }
}
