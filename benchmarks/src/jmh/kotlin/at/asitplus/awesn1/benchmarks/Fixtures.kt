// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.benchmarks

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.awesn1.serialization.ExplicitlyTagged
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.File
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.util.*
import kotlin.uuid.Uuid

/**
 * DER fixtures shared by the benchmarks. The certificate is a real, self-signed X.509 v3 certificate generated
 * once via Bouncy Castle (so it has the canonical `version [0] EXPLICIT`, `extensions [3] EXPLICIT`, and no
 * unique-IDs that the [BenchCertificate] model below expects), guaranteeing both libraries decode identical bytes.
 */
object Fixtures {

    /** A genuine self-signed X.509 v3 certificate, DER-encoded. */
    fun certificateDer(): ByteArray {
        val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val now = Date()
        val notAfter = Date(now.time + 365L * 24 * 60 * 60 * 1000)
        val name = X500Name("CN=awesn1 benchmark,O=A-SIT Plus,C=AT")
        val builder = JcaX509v3CertificateBuilder(name, BigInteger.valueOf(1), now, notAfter, name, keyPair.public)
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(false))
        val signer = JcaContentSignerBuilder("SHA256withRSA").build(keyPair.private)
        return builder.build(signer).encoded
    }

    /** A SEQUENCE of 50 INTEGERs — integer-decoding heavy, shallow. */
    fun integerHeavyDer(): ByteArray = Asn1.Sequence { repeat(50) { +Asn1.Int(it) } }.derEncoded

    /** A small mixed primitive structure. */
    fun mixedSmallDer(): ByteArray = Asn1.Sequence {
        +Asn1.Int(1)
        +Asn1.OctetString(ByteArray(32) { it.toByte() })
        +ObjectIdentifier(Uuid.random())
        +Asn1.Bool(true)
    }.derEncoded

    /** System property carrying the absolute path to `crypto/src/jvmTest/resources` (set by the build). */
    const val CORPUS_PROPERTY = "awesn1.bench.corpus"

    /**
     * Loads a corpus of real-world DER blobs from `crypto/src/jvmTest/resources`: `.der`/`.crt` files are read raw,
     * `.pem` files are split into their base64 blocks and decoded. Whether a given blob actually parses is
     * irrelevant — the corpus benchmark feeds every blob to both parsers and only measures throughput.
     */
    fun loadCorpus(): List<ByteArray> {
        val root = System.getProperty(CORPUS_PROPERTY)?.let(::File)
            ?: error("system property $CORPUS_PROPERTY is not set")
        val out = mutableListOf<ByteArray>()
        root.walkTopDown().filter { it.isFile }.forEach { file ->
            when (file.extension.lowercase()) {
                "der", "crt" -> out += file.readBytes()
                "pem" -> PemBlock.decodeAllFromPem(file.readText()).forEach { out += it.payload }
            }
        }
        return out
    }
}

/**
 * Coarse `@Serializable` X.509 model: the polymorphic/variable parts (algorithm identifiers, names, validity,
 * SPKI, the extension list) are captured as raw [Asn1Element]s, while the framing, explicit context tags and the
 * INTEGER fields exercise the kxs decoder. Works for any v3 certificate carrying `version [0]` and `extensions [3]`.
 */
@Serializable
data class BenchCertificate(
    val tbsCertificate: BenchTbsCertificate,
    val signatureAlgorithm: Asn1Element,
    val signatureValue: Asn1Element,
)

@Serializable
data class BenchTbsCertificate(
    @Asn1Tag(0u, Asn1Tag.Class.CONTEXT_SPECIFIC, Asn1Tag.ConstructedBit.CONSTRUCTED)
    val version: ExplicitlyTagged<Int>,
    val serialNumber: Asn1Integer,
    val signature: Asn1Element,
    val issuer: Asn1Element,
    val validity: Asn1Element,
    val subject: Asn1Element,
    val subjectPublicKeyInfo: Asn1Element,
    @Asn1Tag(3u, Asn1Tag.Class.CONTEXT_SPECIFIC, Asn1Tag.ConstructedBit.CONSTRUCTED)
    val extensions: ExplicitlyTagged<Asn1Element>,
)