// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.viewer

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1EncapsulatingOctetString
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.Asn1Structure
import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.TagClass
import at.asitplus.awesn1.crypto.EncryptedPrivateKeyInfo
import at.asitplus.awesn1.crypto.Pkcs1RsaPrivateKeyInfo
import at.asitplus.awesn1.crypto.Pkcs1RsaPublicKeyInfo
import at.asitplus.awesn1.crypto.Pkcs8PrivateKeyInfo
import at.asitplus.awesn1.crypto.Sec1EcPrivateKeyInfo
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequest
import at.asitplus.awesn1.crypto.pki.X509Certificate
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension
import at.asitplus.awesn1.encoding.decodeToLongOrNull
import at.asitplus.awesn1.serialization.DER
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.decodeFromByteArray
import kotlin.time.Instant

internal val ANDROID_KEY_ATTESTATION_OID = ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")

internal fun registerViewerOids() {
    KnownOIDs[ANDROID_KEY_ATTESTATION_OID] = "androidKeyAttestation (Android key attestation extension)"
}

/**
 * Names the members of [root] if it matches one of the structures the viewer knows. Never throws: schema hints are
 * decoration, so a structure that cannot be recognized (or one whose recognition fails part-way) degrades to fewer
 * names, never to a failed render.
 */
fun schemaMemberNames(bytes: ByteArray, root: Asn1Element): Map<Asn1Path, String> =
    runCatching { recognize(bytes, root) }.getOrDefault(emptyMap())

@OptIn(ExperimentalSerializationApi::class)
private fun recognize(bytes: ByteArray, root: Asn1Element): Map<Asn1Path, String> {
    val children = (root as? Asn1Structure)?.children.orEmpty()
    decode(X509Certificate.serializer(), bytes)?.let { return Names(root).certificate(it) }
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

/**
 * Human-readable renderings for the primitives whose meaning is defined by the schema: the KeyMint/Keymaster
 * enumerations, the packed version and patch-level integers, the epoch-millisecond date tags, and the identifier
 * strings. A primitive that carries no member name of its own inherits the one of its nearest named ancestor, which is
 * how the payload of an `EXPLICIT` context tag (and the members of a `SET OF`) is resolved.
 *
 * Never throws, and degrades per primitive: a value that cannot be rendered semantically keeps its generic rendering.
 */
fun schemaValueNames(root: Asn1Element, memberNames: Map<Asn1Path, String>): Map<Asn1Path, String> = buildMap {
    fun visit(element: Asn1Element, path: Asn1Path) {
        if (element is Asn1Primitive) {
            val member = (0..EXPLICIT_TAG_LOOKUP_DEPTH).firstNotNullOfOrNull { levelsUp ->
                if (levelsUp >= path.size) null else memberNames[path.dropLast(levelsUp)]
            }
            member?.let { runCatching { valueName(it, element) }.getOrNull() }?.let { put(path, it) }
        }
        element.viewerChildren.forEachIndexed { index, child -> visit(child, path + index) }
    }
    visit(root, path(0))
}

/** An `EXPLICIT` tag adds one level, a `SET OF` inside it a second one. */
private const val EXPLICIT_TAG_LOOKUP_DEPTH = 2

private fun valueName(member: String, value: Asn1Primitive): String? {
    val ordinal = when (value.tag) {
        Asn1Element.Tag.INT, Asn1Element.Tag.ENUM -> value.decodeToLongOrNull(value.tag, lenient = true)
        else -> null
    }
    if (ordinal != null) return when (member) {
        "attestationVersion" -> ATTESTATION_VERSIONS[ordinal]
        "keymasterVersion", "keyMintVersion" -> KEYMINT_VERSIONS[ordinal]
        "attestationSecurityLevel", "keymasterSecurityLevel", "keyMintSecurityLevel" -> SECURITY_LEVELS[ordinal]
        "verifiedBootState" -> VERIFIED_BOOT_STATES[ordinal]
        "purpose" -> KEY_PURPOSES[ordinal]
        "algorithm" -> ALGORITHMS[ordinal]
        "blockMode" -> BLOCK_MODES[ordinal]
        "digest", "mgfDigest" -> DIGESTS[ordinal]
        "padding" -> PADDING_MODES[ordinal]
        "ecCurve" -> EC_CURVES[ordinal]
        "mlDsaVariant" -> ML_DSA_VARIANTS[ordinal]
        "origin" -> KEY_ORIGINS[ordinal]
        "userAuthType" -> hardwareAuthenticatorTypes(ordinal)
        "osVersion" -> osVersion(ordinal)
        "osPatchLevel", "vendorPatchLevel", "bootPatchLevel" -> patchLevel(ordinal)
        "activeDateTime", "originationExpireDateTime", "usageExpireDateTime", "creationDateTime" -> dateTime(ordinal)
        else -> null
    }
    if (value.tag == Asn1Element.Tag.OCTET_STRING && member in ASCII_VALUED_MEMBERS) return value.asciiOrNull()
    return null
}

/** `Tag::OS_VERSION` packs `MMmmss` into a single integer, so 8.1.0 is reported as `080100`. */
private fun osVersion(value: Long): String? =
    if (value < 0 || value > 999_999) null else "${value / 10_000}.${value / 100 % 100}.${value % 100}"

/**
 * `Tag::OS_PATCHLEVEL` is `YYYYMM`; `Tag::VENDOR_PATCHLEVEL` and `Tag::BOOT_PATCHLEVEL` are the security patch date
 * with the dashes removed, i.e. `YYYYMMDD`.
 */
private fun patchLevel(value: Long): String? = when {
    value in 100_000..999_999 -> "${value / 100}-${(value % 100).twoDigits()}"
    value in 10_000_000..99_999_999 -> "${value / 10_000}-${(value / 100 % 100).twoDigits()}-${(value % 100).twoDigits()}"
    else -> null
}

/** Tags of KeyMint type `DATE` carry milliseconds since Jan 1, 1970 00:00:00 GMT. */
private fun dateTime(value: Long): String? = runCatching { Instant.fromEpochMilliseconds(value).toString() }.getOrNull()

/** `Tag::USER_AUTH_TYPE` is a bit mask of [HardwareAuthenticatorType][HARDWARE_AUTHENTICATOR_TYPES] values. */
private fun hardwareAuthenticatorTypes(value: Long): String? = when {
    value == 0L -> "None"
    value == -1L || value == 0xFFFFFFFFL -> "Any"
    value < 0 || value > 0xFFFFFFFFL -> null
    else -> (0..31).filter { (value shr it) and 1L == 1L }
        .joinToString(" | ") { HARDWARE_AUTHENTICATOR_TYPES[1L shl it] ?: "bit $it" }
}

/** Identifiers such as the device brand or an attested package name are plain ASCII inside an `OCTET STRING`. */
private fun Asn1Primitive.asciiOrNull(): String? {
    val bytes = content
    if (bytes.isEmpty() || bytes.size > MAX_RENDERED_ASCII_BYTES) return null
    if (!bytes.all { it.toInt() in 0x20..0x7e }) return null
    return "\"${bytes.decodeToString()}\""
}

private const val MAX_RENDERED_ASCII_BYTES = 128

private fun Long.twoDigits() = toString().padStart(2, '0')

internal fun androidKeyAttestationSchemaNames(root: Asn1Element): Map<Asn1Path, String> =
    Names(root).androidKeyAttestation(path(0))

@OptIn(ExperimentalSerializationApi::class)
private fun <T> decode(serializer: KSerializer<T>, bytes: ByteArray): T? =
    runCatching { DER.decodeFromByteArray(serializer, bytes) }.getOrNull()

private fun path(vararg indexes: Int): Asn1Path = indexes.toList()

private class Names(private val root: Asn1Element) {
    private val result = mutableMapOf<Asn1Path, String>()

    /**
     * Runs [block] and returns whatever it managed to name. Schema hints are decoration layered onto a tree that
     * renders without them, so a partially enriched tree always beats aborting the render.
     */
    private inline fun build(block: () -> Unit): Map<Asn1Path, String> {
        runCatching(block)
        return result
    }

    fun certificate(certificate: X509Certificate): Map<Asn1Path, String> = build {
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
                3uL -> extensions(childPath, certificate.tbsCertificate.extensions.orEmpty())
            }
            index++
        }
        algorithm(path(0, 1), "signatureAlgorithm")
        name(path(0, 2), "signatureValue")
    }

    fun csr(): Map<Asn1Path, String> = build {
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
    }

    fun pkcs8(key: Pkcs8PrivateKeyInfo): Map<Asn1Path, String> = build {
        name(path(0), "PrivateKeyInfo")
        name(path(0, 0), "version")
        algorithm(path(0, 1), "privateKeyAlgorithm")
        name(path(0, 2), "privateKey")
        if (node(path(0)).childCount > 3) name(path(0, 3), "attributes")
        when {
            runCatching { Pkcs1RsaPrivateKeyInfo.of(key) }.isSuccess -> rsaPrivate(path(0, 2, 0), "RSAPrivateKey")
            runCatching { Sec1EcPrivateKeyInfo.of(key) }.isSuccess -> ecPrivate(path(0, 2, 0), "ECPrivateKey")
        }
    }

    fun encryptedPrivateKey(): Map<Asn1Path, String> = build {
        name(path(0), "EncryptedPrivateKeyInfo")
        algorithm(path(0, 0), "encryptionAlgorithm")
        name(path(0, 1), "encryptedData")
    }

    fun rsaPrivate(rootPath: Asn1Path, rootName: String = "RSAPrivateKey"): Map<Asn1Path, String> = build {
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
    }

    fun ecPrivate(rootPath: Asn1Path, rootName: String = "ECPrivateKey"): Map<Asn1Path, String> = build {
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
    }

    fun subjectPublicKeyInfo(rootPath: Asn1Path, rootName: String): Map<Asn1Path, String> = build {
        name(rootPath, rootName)
        algorithm(rootPath + 0, "algorithm")
        name(rootPath + 1, "subjectPublicKey")
    }

    fun rsaPublic(rootPath: Asn1Path): Map<Asn1Path, String> = build {
        name(rootPath, "RSAPublicKey")
        name(rootPath + 0, "modulus")
        name(rootPath + 1, "publicExponent")
    }

    fun androidKeyAttestation(rootPath: Asn1Path): Map<Asn1Path, String> = build {
        name(rootPath, "KeyDescription")
        name(rootPath + 0, "attestationVersion")
        name(rootPath + 1, "attestationSecurityLevel")
        val version = (node(rootPath + 0) as? Asn1Primitive)?.decodeToLongOrNull()
        val implementation = if (version != null && version >= 100) "keyMint" else "keymaster"
        name(rootPath + 2, "${implementation}Version")
        name(rootPath + 3, "${implementation}SecurityLevel")
        name(rootPath + 4, "attestationChallenge")
        name(rootPath + 5, "uniqueId")
        authorizationList(rootPath + 6, "softwareEnforced")
        authorizationList(rootPath + 7, "hardwareEnforced")
    }

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

    private fun extensions(taggedPath: Asn1Path, decodedExtensions: List<X509CertificateExtension>) {
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
            if (decodedExtensions.getOrNull(index)?.oid == ANDROID_KEY_ATTESTATION_OID)
                node(extension + child).children.singleOrNull()?.let { androidKeyAttestation(extension + child + 0) }
        }
    }

    private fun authorizationList(rootPath: Asn1Path, member: String) {
        name(rootPath, member)
        node(rootPath).children.forEachIndexed { index, element ->
            if (element.tag.tagClass == TagClass.CONTEXT_SPECIFIC) {
                val taggedPath = rootPath + index
                AUTHORIZATION_TAG_NAMES[element.tag.tagValue]?.let { name(taggedPath, it) }
                when (element.tag.tagValue) {
                    704uL -> rootOfTrust(taggedPath + 0)
                    709uL -> attestationApplicationId(taggedPath + 0)
                }
            }
        }
    }

    private fun rootOfTrust(rootPath: Asn1Path) {
        name(rootPath, "RootOfTrust")
        name(rootPath + 0, "verifiedBootKey")
        name(rootPath + 1, "deviceLocked")
        name(rootPath + 2, "verifiedBootState")
        name(rootPath + 3, "verifiedBootHash")
    }

    /** The `attestationApplicationId` OCTET STRING wraps a DER-encoded `AttestationApplicationId`. */
    private fun attestationApplicationId(octetStringPath: Asn1Path) {
        val rootPath = octetStringPath + 0
        if (node(rootPath) == null) return
        name(rootPath, "AttestationApplicationId")
        val packageInfos = rootPath + 0
        name(packageInfos, "package_infos")
        node(packageInfos).children.forEachIndexed { index, _ ->
            val packageInfo = packageInfos + index
            name(packageInfo, "AttestationPackageInfo")
            name(packageInfo + 0, "package_name")
            name(packageInfo + 1, "version")
        }
        val signatureDigests = rootPath + 1
        name(signatureDigests, "signature_digests")
        node(signatureDigests).children.forEachIndexed { index, _ -> name(signatureDigests + index, "signature_digest") }
    }

    private fun name(path: Asn1Path, value: String) {
        if (node(path) != null) result[path] = value
    }

    private fun node(path: Asn1Path): Asn1Element? = path.drop(1).fold(root as Asn1Element?) { current, index ->
        current.children.getOrNull(index)
    }

    private val Asn1Element?.children: List<Asn1Element> get() = viewerChildren

    private val Asn1Element?.childCount get() = children.size
    private fun Asn1Element.isContext(number: ULong) = tag.tagClass == TagClass.CONTEXT_SPECIFIC && tag.tagValue == number
}

private val Asn1Element?.viewerChildren: List<Asn1Element>
    get() = when (this) {
        is Asn1Structure -> children
        is Asn1EncapsulatingOctetString -> children
        else -> emptyList()
    }

/** Union of the AuthorizationList tags in Android attestation schema versions 1 through 500. */
private val AUTHORIZATION_TAG_NAMES = mapOf(
    1uL to "purpose",
    2uL to "algorithm",
    3uL to "keySize",
    4uL to "blockMode",
    5uL to "digest",
    6uL to "padding",
    7uL to "callerNonce",
    8uL to "minMacLength",
    10uL to "ecCurve",
    11uL to "mlDsaVariant",
    200uL to "rsaPublicExponent",
    203uL to "mgfDigest",
    303uL to "rollbackResistance",
    305uL to "earlyBootOnly",
    400uL to "activeDateTime",
    401uL to "originationExpireDateTime",
    402uL to "usageExpireDateTime",
    405uL to "usageCountLimit",
    502uL to "userSecureId",
    503uL to "noAuthRequired",
    504uL to "userAuthType",
    505uL to "authTimeout",
    506uL to "allowWhileOnBody",
    507uL to "trustedUserPresenceReq",
    508uL to "trustedConfirmationReq",
    509uL to "unlockedDeviceReq",
    600uL to "allApplications",
    701uL to "creationDateTime",
    702uL to "origin",
    703uL to "rollbackResistant",
    704uL to "rootOfTrust",
    705uL to "osVersion",
    706uL to "osPatchLevel",
    709uL to "attestationApplicationId",
    710uL to "attestationIdBrand",
    711uL to "attestationIdDevice",
    712uL to "attestationIdProduct",
    713uL to "attestationIdSerial",
    714uL to "attestationIdImei",
    715uL to "attestationIdMeid",
    716uL to "attestationIdManufacturer",
    717uL to "attestationIdModel",
    718uL to "vendorPatchLevel",
    719uL to "bootPatchLevel",
    720uL to "deviceUniqueAttestation",
    723uL to "attestationIdSecondImei",
    724uL to "moduleHash",
)

/** `KeyDescription.attestationVersion`: the schema version of the attestation extension. */
private val ATTESTATION_VERSIONS = mapOf(
    1L to "Keymaster 2.0",
    2L to "Keymaster 3.0",
    3L to "Keymaster 4.0",
    4L to "Keymaster 4.1",
    100L to "KeyMint 1.0",
    200L to "KeyMint 2.0",
    300L to "KeyMint 3.0",
    400L to "KeyMint 4.0",
    500L to "KeyMint 5.0",
)

/** `KeyDescription.keymasterVersion` / `keyMintVersion`: the version of the HAL implementation. */
private val KEYMINT_VERSIONS = mapOf(
    2L to "Keymaster 2.0",
    3L to "Keymaster 3.0",
    4L to "Keymaster 4.0",
    41L to "Keymaster 4.1",
    100L to "KeyMint 1.0",
    200L to "KeyMint 2.0",
    300L to "KeyMint 3.0",
    400L to "KeyMint 4.0",
    500L to "KeyMint 5.0",
)

/** `SecurityLevel`, extended by `SecurityLevel::KEYSTORE` from the KeyMint AIDL. */
private val SECURITY_LEVELS = mapOf(
    0L to "Software",
    1L to "TrustedEnvironment",
    2L to "StrongBox",
    100L to "Keystore",
)

/** `VerifiedBootState`. */
private val VERIFIED_BOOT_STATES = mapOf(
    0L to "Verified",
    1L to "SelfSigned",
    2L to "Unverified",
    3L to "Failed",
)

/** `KeyPurpose`; 4 is unused since Keymaster's `DERIVE_KEY` was dropped. */
private val KEY_PURPOSES = mapOf(
    0L to "Encrypt",
    1L to "Decrypt",
    2L to "Sign",
    3L to "Verify",
    4L to "DeriveKey (Keymaster only)",
    5L to "WrapKey",
    6L to "AgreeKey",
    7L to "AttestKey",
)

/** `Algorithm`; 2 is Keymaster's dropped `DSA`. In an attestation this is always RSA, EC or ML-DSA. */
private val ALGORITHMS = mapOf(
    1L to "RSA",
    2L to "DSA (Keymaster only)",
    3L to "EC",
    4L to "ML-DSA",
    32L to "AES",
    33L to "TripleDES",
    128L to "HMAC",
)

/** `BlockMode`. */
private val BLOCK_MODES = mapOf(
    1L to "ECB",
    2L to "CBC",
    3L to "CTR",
    32L to "GCM",
)

/** `Digest`, used by both `digest` and `mgfDigest`. */
private val DIGESTS = mapOf(
    0L to "None",
    1L to "MD5",
    2L to "SHA-1",
    3L to "SHA-224",
    4L to "SHA-256",
    5L to "SHA-384",
    6L to "SHA-512",
)

/** `PaddingMode`. */
private val PADDING_MODES = mapOf(
    1L to "None",
    2L to "RSA-OAEP",
    3L to "RSA-PSS",
    4L to "RSA-PKCS1-1.5-Encrypt",
    5L to "RSA-PKCS1-1.5-Sign",
    64L to "PKCS7",
)

/** `EcCurve`. */
private val EC_CURVES = mapOf(
    0L to "P-224",
    1L to "P-256",
    2L to "P-384",
    3L to "P-521",
    4L to "Curve25519",
)

/** `MlDsaVariant`; ML-DSA-44 is deliberately not supported by KeyMint. */
private val ML_DSA_VARIANTS = mapOf(
    1L to "ML-DSA-65",
    2L to "ML-DSA-87",
)

/** `KeyOrigin`. */
private val KEY_ORIGINS = mapOf(
    0L to "Generated",
    1L to "Derived",
    2L to "Imported",
    3L to "Reserved",
    4L to "SecurelyImported",
)

/** `HardwareAuthenticatorType`, keyed by the individual bit; `NONE` and `ANY` are handled separately. */
private val HARDWARE_AUTHENTICATOR_TYPES = mapOf(
    1L to "Password",
    2L to "Fingerprint",
)

/** Members whose OCTET STRING content is a plain identifier string rather than opaque bytes. */
private val ASCII_VALUED_MEMBERS = setOf(
    "attestationChallenge",
    "attestationIdBrand",
    "attestationIdDevice",
    "attestationIdProduct",
    "attestationIdSerial",
    "attestationIdImei",
    "attestationIdMeid",
    "attestationIdManufacturer",
    "attestationIdModel",
    "attestationIdSecondImei",
    "package_name",
)
