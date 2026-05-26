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
 * As per [RFC2986](https://www.rfc-editor.org/rfc/rfc2986.html#section-4):
 * ```
 * CertificationRequest ::= SEQUENCE {
 *   certificationRequestInfo  CertificationRequestInfo,
 *   signatureAlgorithm        AlgorithmIdentifier{{ SignatureAlgorithms }},
 *   signature                 BIT STRING
 * }
 * ```
 */
@Serializable
data class Pkcs10CertificationRequest(
    val certificationRequestInfo: Pkcs10CertificationRequestInfo,
    val signatureAlgorithm: X509AlgorithmIdentifier,
    val signatureValue: X509SignatureValue,
) : WithPemLabel {
    override val pemLabel: String get() = PEM_LABEL

    companion object : PemLabelSpec<Pkcs10CertificationRequest> {
        const val PEM_LABEL = "CERTIFICATE REQUEST"

        override val canonicalPemLabel: String get() = PEM_LABEL

        override val alternativePemLabels: Set<String> = setOf("NEW CERTIFICATE REQUEST")
    }
}
