// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.awesn1.serialization.ExplicitlyTagged
import at.asitplus.awesn1.toInt
import kotlinx.serialization.Serializable

/**
 *
 * As per [RFC5915](https://www.rfc-editor.org/rfc/rfc5915.html#section-3):
 * ```
 * ECPrivateKey ::= SEQUENCE {
 *   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
 *   privateKey     OCTET STRING,
 *   parameters [0] ECParameters OPTIONAL,
 *   publicKey  [1] BIT STRING OPTIONAL
 * }
 * ```
 *
 * (See also [errata](https://www.rfc-editor.org/errata/rfc5915)
 */
@Serializable
data class Sec1EcPrivateKeyInfo(
    override val rawVersion: Asn1Integer,
    val privateKey: ByteArray,
    @Asn1Tag(tagNumber = 0u)
    val parameters: ExplicitlyTagged<ObjectIdentifier>? = null,
    @Asn1Tag(tagNumber = 1u)
    val publicKey: ExplicitlyTagged<Asn1BitString>? = null,
): Versioned {
    constructor(
        version: Int = 1,
        privateKey: ByteArray,
        parameters: ObjectIdentifier?,
        publicKey: Asn1BitString?,
    ) : this(
        rawVersion = Asn1Integer(version),
        privateKey = privateKey,
        parameters = parameters?.let(::ExplicitlyTagged),
        publicKey = publicKey?.let(::ExplicitlyTagged),
    )

    /**
     *
     * The integer must fit the valid Int value range (within Int.MIN_VALUE..Int.MAX_VALUE), otherwise a [NumberFormatException] will be thrown.
     */
    @get:Throws(NumberFormatException::class)
    override val version: Int? by lazy { rawVersion.toInt() }

    override fun equals(other: Any?): Boolean =
        other is Sec1EcPrivateKeyInfo &&
                rawVersion == other.rawVersion &&
                privateKey.contentEquals(other.privateKey) &&
                parameters == other.parameters &&
                publicKey == other.publicKey

    override fun hashCode(): Int {
        var result = rawVersion.hashCode()
        result = 31 * result + privateKey.contentHashCode()
        result = 31 * result + (parameters?.hashCode() ?: 0)
        result = 31 * result + (publicKey?.hashCode() ?: 0)
        return result
    }
}
