// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1OctetString
import at.asitplus.awesn1.WithPemLabel
import at.asitplus.awesn1.PemLabelSpec
import kotlinx.serialization.Serializable

/**
 *
 * As per [RFC5208](https://www.rfc-editor.org/rfc/rfc5208.html#section-6):
 * ```
 * EncryptedPrivateKeyInfo ::= SEQUENCE {
 *   encryptionAlgorithm  EncryptionAlgorithmIdentifier,
 *   encryptedData        EncryptedData
 * }
 *
 * EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
 * EncryptedData ::= OCTET STRING
 * ```
 */
@Serializable
data class EncryptedPrivateKeyInfo(
    val encryptionAlgorithm: X509AlgorithmIdentifier,
    @Suppress("SERIALIZER_TYPE_INCOMPATIBLE")
    val encryptedData: Asn1OctetString,
) : WithPemLabel {
    override val pemLabel: String get() = PEM_LABEL

    companion object : PemLabelSpec<EncryptedPrivateKeyInfo> {
        const val PEM_LABEL = "ENCRYPTED PRIVATE KEY"
        override val canonicalPemLabel: String get() = PEM_LABEL
    }
}
