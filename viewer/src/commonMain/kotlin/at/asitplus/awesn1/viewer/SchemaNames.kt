// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.viewer

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1EncapsulatingOctetString
import at.asitplus.awesn1.Asn1Structure
import at.asitplus.awesn1.TagClass
import at.asitplus.awesn1.crypto.EncryptedPrivateKeyInfo
import at.asitplus.awesn1.crypto.Pkcs1RsaPrivateKeyInfo
import at.asitplus.awesn1.crypto.Pkcs1RsaPublicKeyInfo
import at.asitplus.awesn1.crypto.Pkcs8PrivateKeyInfo
import at.asitplus.awesn1.crypto.Sec1EcPrivateKeyInfo
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequest
import at.asitplus.awesn1.crypto.pki.X509Certificate
import at.asitplus.awesn1.serialization.DER
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.decodeFromByteArray

@OptIn(ExperimentalSerializationApi::class)
fun schemaMemberNames(bytes: ByteArray, root: Asn1Element): Map<Asn1Path, String> {
    val children = (root as? Asn1Structure)?.children.orEmpty()
    decode(X509Certificate.serializer(), bytes)?.let { return Names(root).certificate() }
    decode(Pkcs10CertificationRequest.serializer(), bytes)?.let { return Names(root).csr() }
    if (children.size >= 3 && children[0].tag == Asn1Element.Tag.INT && children[1].tag == Asn1Element.Tag.SEQUENCE && children[2].tag == Asn1Element.Tag.OCTET_STRING)
        decode(Pkcs8PrivateKeyInfo.serializer(), bytes)?.let { key -> return Names(root).pkcs8(key) }
    if (children.size == 2 && children[0].tag == Asn1Element.Tag.SEQUENCE && children[1].tag == Asn1Element.Tag.OCTET_STRING)
        decode(EncryptedPrivateKeyInfo.serializer(), bytes)?.let { return Names(root).encryptedPrivateKey() }
    if (children.size >= 9 && children.all { it.tag == Asn1Element.Tag.INT })
        decode(Pkcs1RsaPrivateKeyInfo.serializer(), bytes)?.let { return Names(root).rsaPrivate(path(0)) }
    if (children.size in 2..4 && children[0].tag == Asn1Element.Tag.INT && children[1].tag == Asn1Element.Tag.OCTET_STRING)
        decode(Sec1EcPrivateKeyInfo.serializer(), bytes)?.let { return Names(root).ecPrivate(path(0)) }
    if (children.size == 2 && children[0].tag == Asn1Element.Tag.SEQUENCE && children[1].tag == Asn1Element.Tag.BIT_STRING)
        decode(SubjectPublicKeyInfo.serializer(), bytes)?.let { return Names(root).subjectPublicKeyInfo(path(0), "SubjectPublicKeyInfo") }
    if (children.size == 2 && children.all { it.tag == Asn1Element.Tag.INT })
        decode(Pkcs1RsaPublicKeyInfo.serializer(), bytes)?.let { return Names(root).rsaPublic(path(0)) }
    return emptyMap()
}

@OptIn(ExperimentalSerializationApi::class)
private fun <T> decode(serializer: KSerializer<T>, bytes: ByteArray): T? =
    runCatching { DER.decodeFromByteArray(serializer, bytes) }.getOrNull()

private fun path(vararg indexes: Int): Asn1Path = indexes.toList()

private class Names(private val root: Asn1Element) {
    private val result = mutableMapOf<Asn1Path, String>()

    fun certificate(): Map<Asn1Path, String> = apply {
        name(path(0), "Certificate")
        val tbs = path(0, 0)
        name(tbs, "tbsCertificate")
        var index = 0
        if (node(tbs + index)?.isContext(0uL) == true) {
            name(tbs + index, "version")
            name(tbs + index + 0, "Version")
            index++
        }
        name(tbs + index++, "serialNumber")
        algorithm(tbs + index++, "signature")
        x500Name(tbs + index++, "issuer")
        val validity = tbs + index++
        name(validity, "validity")
        name(validity + 0, "notBefore")
        name(validity + 1, "notAfter")
        x500Name(tbs + index++, "subject")
        subjectPublicKeyInfo(tbs + index++, "subjectPublicKeyInfo")
        while (node(tbs).childCount > index) {
            val childPath = tbs + index
            when (node(childPath)?.tag?.tagValue) {
                1uL -> name(childPath, "issuerUniqueID")
                2uL -> name(childPath, "subjectUniqueID")
                3uL -> extensions(childPath)
            }
            index++
        }
        algorithm(path(0, 1), "signatureAlgorithm")
        name(path(0, 2), "signatureValue")
    }.result

    fun csr(): Map<Asn1Path, String> = apply {
        name(path(0), "CertificationRequest")
        name(path(0, 0), "certificationRequestInfo")
        name(path(0, 0, 0), "version")
        x500Name(path(0, 0, 1), "subject")
        subjectPublicKeyInfo(path(0, 0, 2), "subjectPKInfo")
        val attributes = path(0, 0, 3)
        name(attributes, "attributes")
        node(attributes).children.forEachIndexed { index, _ ->
            val attribute = attributes + index
            name(attribute, "Attribute")
            name(attribute + 0, "type")
            name(attribute + 1, "values")
            node(attribute + 1).children.forEachIndexed { valueIndex, _ ->
                name(attribute + 1 + valueIndex, "AttributeValue")
            }
        }
        algorithm(path(0, 1), "signatureAlgorithm")
        name(path(0, 2), "signature")
    }.result

    fun pkcs8(key: Pkcs8PrivateKeyInfo): Map<Asn1Path, String> = apply {
        name(path(0), "PrivateKeyInfo")
        name(path(0, 0), "version")
        algorithm(path(0, 1), "privateKeyAlgorithm")
        name(path(0, 2), "privateKey")
        if (node(path(0)).childCount > 3) name(path(0, 3), "attributes")
        when {
            runCatching { Pkcs1RsaPrivateKeyInfo.of(key) }.isSuccess -> rsaPrivate(path(0, 2, 0), "RSAPrivateKey")
            runCatching { Sec1EcPrivateKeyInfo.of(key) }.isSuccess -> ecPrivate(path(0, 2, 0), "ECPrivateKey")
        }
    }.result

    fun encryptedPrivateKey(): Map<Asn1Path, String> = apply {
        name(path(0), "EncryptedPrivateKeyInfo")
        algorithm(path(0, 0), "encryptionAlgorithm")
        name(path(0, 1), "encryptedData")
    }.result

    fun rsaPrivate(rootPath: Asn1Path, rootName: String = "RSAPrivateKey"): Map<Asn1Path, String> = apply {
        name(rootPath, rootName)
        listOf("version", "modulus", "publicExponent", "privateExponent", "prime1", "prime2", "exponent1", "exponent2", "coefficient")
            .forEachIndexed { index, member -> name(rootPath + index, member) }
        if (node(rootPath).childCount > 9) {
            val others = rootPath + 9
            name(others, "otherPrimeInfos")
            node(others).children.forEachIndexed { index, _ ->
                val other = others + index
                name(other, "OtherPrimeInfo")
                name(other + 0, "prime")
                name(other + 1, "exponent")
                name(other + 2, "coefficient")
            }
        }
    }.result

    fun ecPrivate(rootPath: Asn1Path, rootName: String = "ECPrivateKey"): Map<Asn1Path, String> = apply {
        name(rootPath, rootName)
        name(rootPath + 0, "version")
        name(rootPath + 1, "privateKey")
        for (index in 2 until node(rootPath).childCount) {
            val child = rootPath + index
            when (node(child)?.tag?.tagValue) {
                0uL -> name(child, "parameters")
                1uL -> name(child, "publicKey")
            }
        }
    }.result

    fun subjectPublicKeyInfo(rootPath: Asn1Path, rootName: String): Map<Asn1Path, String> = apply {
        name(rootPath, rootName)
        algorithm(rootPath + 0, "algorithm")
        name(rootPath + 1, "subjectPublicKey")
    }.result

    fun rsaPublic(rootPath: Asn1Path): Map<Asn1Path, String> = apply {
        name(rootPath, "RSAPublicKey")
        name(rootPath + 0, "modulus")
        name(rootPath + 1, "publicExponent")
    }.result

    private fun algorithm(rootPath: Asn1Path, member: String) {
        name(rootPath, member)
        name(rootPath + 0, "algorithm")
        if (node(rootPath).childCount > 1) name(rootPath + 1, "parameters")
    }

    private fun x500Name(rootPath: Asn1Path, member: String) {
        name(rootPath, member)
        node(rootPath).children.forEachIndexed { rdnIndex, rdn ->
            val rdnPath = rootPath + rdnIndex
            name(rdnPath, "RelativeDistinguishedName")
            rdn.children.forEachIndexed { attributeIndex, _ ->
                val attribute = rdnPath + attributeIndex
                name(attribute, "AttributeTypeAndValue")
                name(attribute + 0, "type")
                name(attribute + 1, "value")
            }
        }
    }

    private fun extensions(taggedPath: Asn1Path) {
        name(taggedPath, "extensions")
        val sequence = taggedPath + 0
        name(sequence, "Extensions")
        node(sequence).children.forEachIndexed { index, extensionElement ->
            val extension = sequence + index
            name(extension, "Extension")
            name(extension + 0, "extnID")
            var child = 1
            if (extensionElement.children.getOrNull(child)?.tag == Asn1Element.Tag.BOOL) {
                name(extension + child, "critical")
                child++
            }
            name(extension + child, "extnValue")
        }
    }

    private fun name(path: Asn1Path, value: String) {
        if (node(path) != null) result[path] = value
    }

    private fun node(path: Asn1Path): Asn1Element? = path.drop(1).fold(root as Asn1Element?) { current, index ->
        current.children.getOrNull(index)
    }

    private val Asn1Element?.children: List<Asn1Element>
        get() = when (this) {
            is Asn1Structure -> children
            is Asn1EncapsulatingOctetString -> children
            else -> emptyList()
        }

    private val Asn1Element?.childCount get() = children.size
    private fun Asn1Element.isContext(number: ULong) = tag.tagClass == TagClass.CONTEXT_SPECIFIC && tag.tagValue == number
}
