// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

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
) {
    companion object {
        const val PEM_LABEL = "CERTIFICATE"
    }
}
