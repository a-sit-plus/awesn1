// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1PrimitiveOctetString
import kotlinx.serialization.Serializable

@Serializable
data class EncryptedPrivateKeyInfo(
    val encryptionAlgorithm: Asn1Element,
    val encryptedData: Asn1Element,
) {
    constructor(
        encryptionAlgorithm: Asn1Element,
        encryptedData: Asn1PrimitiveOctetString,
    ) : this(encryptionAlgorithm, encryptedData as Asn1Element)

    companion object {
        const val PEM_LABEL = "ENCRYPTED PRIVATE KEY"
    }
}
