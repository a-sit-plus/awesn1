// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.WithPemLabel
import at.asitplus.awesn1.WithValidPemLabels
import at.asitplus.awesn1.crypto.SignatureValue
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
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
    val signatureValue: SignatureValue,
) : WithPemLabel {
    override val pemLabel: String get() = canonicalPemLabel

    companion object : WithValidPemLabels<X509Certificate> {
        override val canonicalPemLabel: String get() = "CERTIFICATE"
    }
}
