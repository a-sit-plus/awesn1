// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.serialization.Asn1ConstructedBit
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.awesn1.serialization.ExplicitlyTagged
import kotlinx.serialization.Serializable

@Serializable
data class EcPrivateKeyInfo(
    val version: Int,
    val privateKey: ByteArray,
    @Asn1Tag(tagNumber = 0u, constructed = Asn1ConstructedBit.CONSTRUCTED)
    val parameters: ExplicitlyTagged<ObjectIdentifier>? = null,
    @Asn1Tag(tagNumber = 1u, constructed = Asn1ConstructedBit.CONSTRUCTED)
    val publicKey: ExplicitlyTagged<Asn1BitString>? = null,
) {
    constructor(
        version: Int,
        privateKey: ByteArray,
        parameters: ObjectIdentifier?,
        publicKey: Asn1BitString?,
    ) : this(
        version = version,
        privateKey = privateKey,
        parameters = parameters?.let(::ExplicitlyTagged),
        publicKey = publicKey?.let(::ExplicitlyTagged),
    )

    override fun equals(other: Any?): Boolean =
        other is EcPrivateKeyInfo &&
            version == other.version &&
            privateKey.contentEquals(other.privateKey) &&
            parameters == other.parameters &&
            publicKey == other.publicKey

    override fun hashCode(): Int {
        var result = version
        result = 31 * result + privateKey.contentHashCode()
        result = 31 * result + (parameters?.hashCode() ?: 0)
        result = 31 * result + (publicKey?.hashCode() ?: 0)
        return result
    }
}
