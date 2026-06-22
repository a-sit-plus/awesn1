// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.benchmarks

import at.asitplus.awesn1.serialization.DER
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import org.bouncycastle.asn1.ASN1Encoding
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.x509.Certificate
import org.openjdk.jmh.annotations.Benchmark
import org.openjdk.jmh.annotations.Scope
import org.openjdk.jmh.annotations.Setup
import org.openjdk.jmh.annotations.State

/**
 * Structured certificate decode/encode: awesn1's kotlinx.serialization layer ([DER] into [BenchCertificate]) vs
 * Bouncy Castle's typed X.509 model. Unlike the raw TLV benchmark this builds a typed object graph, so it measures
 * the serialization/deserialization machinery on top of the TLV layer (the closest fair comparison to BC's
 * `org.bouncycastle.asn1.x509.Certificate`).
 */
@State(Scope.Benchmark)
open class CertificateBenchmark {

    private lateinit var certDer: ByteArray
    private lateinit var awesn1Cert: BenchCertificate
    private lateinit var bcCert: Certificate

    @Setup
    fun setup() {
        certDer = Fixtures.certificateDer()
        awesn1Cert = DER.decodeFromByteArray(certDer)
        bcCert = Certificate.getInstance(ASN1Primitive.fromByteArray(certDer))
        // sanity: the kxs model must faithfully round-trip the certificate back to the exact DER bytes
        val reEncoded = DER.encodeToByteArray(awesn1Cert)
        require(reEncoded.contentEquals(certDer)) { "kxs certificate model does not round-trip to identical DER" }
    }

    @Benchmark
    fun awesn1KxsDecode(): BenchCertificate = DER.decodeFromByteArray(certDer)

    @Benchmark
    fun bouncyCastleDecode(): Certificate = Certificate.getInstance(ASN1Primitive.fromByteArray(certDer))

    @Benchmark
    fun awesn1KxsEncode(): ByteArray = DER.encodeToByteArray(awesn1Cert)

    @Benchmark
    fun bouncyCastleEncode(): ByteArray = bcCert.getEncoded(ASN1Encoding.DER)
}