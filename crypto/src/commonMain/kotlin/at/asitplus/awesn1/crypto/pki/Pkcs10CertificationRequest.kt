// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.crypto.AlgorithmIdentifier
import at.asitplus.awesn1.crypto.SignatureValue
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
    val signatureAlgorithm: AlgorithmIdentifier,
    val signatureValue: SignatureValue,
) {
    companion object {
        //NOT PEM DECODCABLE/ENCODABLE to avoid infinite recursion.
        const val PEM_LABEL = "CERTIFICATE REQUEST"
    }
}
