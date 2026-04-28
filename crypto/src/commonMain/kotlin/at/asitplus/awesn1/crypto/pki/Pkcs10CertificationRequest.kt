// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.crypto.SignatureAlgorithmIdentifier
import at.asitplus.awesn1.crypto.SignatureValue
import kotlinx.serialization.Serializable

@Serializable
data class Pkcs10CertificationRequest(
    val certificationRequestInfo: Pkcs10CertificationRequestInfo,
    val signatureAlgorithm: SignatureAlgorithmIdentifier,
    val signatureValue: SignatureValue,
) {
    companion object {
        const val PEM_LABEL = "CERTIFICATE REQUEST"
    }
}
