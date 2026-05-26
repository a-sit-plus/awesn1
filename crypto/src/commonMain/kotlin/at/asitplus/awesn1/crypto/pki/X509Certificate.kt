// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.PemLabelSpec
import at.asitplus.awesn1.WithPemLabel
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.crypto.X509SignatureValue
import kotlinx.serialization.Serializable

/**
 *
 * As per [RFC5280](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1):
 * ```
 * Certificate ::= SEQUENCE {
 *   tbsCertificate       TBSCertificate,
 *   signatureAlgorithm   AlgorithmIdentifier,
 *   signatureValue       BIT STRING
 * }
 * ```
 */
@Serializable
data class X509Certificate(
    val tbsCertificate: X509TbsCertificate,
    val signatureAlgorithm: X509AlgorithmIdentifier,
    val signatureValue: X509SignatureValue,
) : WithPemLabel {
    override val pemLabel: String get() = PEM_LABEL

    companion object : PemLabelSpec<X509Certificate> {
        const val PEM_LABEL = "CERTIFICATE"
        override val canonicalPemLabel: String get() = PEM_LABEL
        override val alternativePemLabels get() = setOf("TRUSTED CERTIFICATE")
    }
}
