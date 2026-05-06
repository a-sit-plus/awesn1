// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.awesn1.serialization.ExplicitlyTagged
import at.asitplus.awesn1.serialization.getValue
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
    private val taggedParameters: ExplicitlyTagged<ObjectIdentifier>? = null,
    @Asn1Tag(tagNumber = 1u)
    private val taggedPublicKey: ExplicitlyTagged<Asn1BitString>? = null,
) : Versioned {
    constructor(
        version: Int = 1,
        privateKey: ByteArray,
        parameters: ObjectIdentifier?,
        publicKey: Asn1BitString?,
    ) : this(
        rawVersion = Asn1Integer(version),
        privateKey = privateKey,
        taggedParameters = parameters?.let(::ExplicitlyTagged),
        taggedPublicKey = publicKey?.let(::ExplicitlyTagged),
    )

    /**
     *
     * The integer must fit the valid Int value range (within Int.MIN_VALUE..Int.MAX_VALUE), otherwise a [NumberFormatException] will be thrown.
     *
     * Getter may throw but we cannot annotate due to https://youtrack.jetbrains.com/issue/KT-63047/Throws-annotation-on-getter-leads-to-compile-time-error-for-iOS-target
     */
    override val version: Int? by lazy { rawVersion.toInt() }

    val parameters: ObjectIdentifier? by taggedParameters

    val publicKey: Asn1BitString? by taggedPublicKey

    override fun equals(other: Any?): Boolean =
        other is Sec1EcPrivateKeyInfo &&
                rawVersion == other.rawVersion &&
                privateKey.contentEquals(other.privateKey) &&
                taggedParameters == other.taggedParameters &&
                taggedPublicKey == other.taggedPublicKey

    override fun hashCode(): Int {
        var result = rawVersion.hashCode()
        result = 31 * result + privateKey.contentHashCode()
        result = 31 * result + (taggedParameters?.hashCode() ?: 0)
        result = 31 * result + (taggedPublicKey?.hashCode() ?: 0)
        return result
    }

    override fun toString(): String {
        return "Sec1EcPrivateKeyInfo(" +
                "rawVersion=$rawVersion, " +
                "privateKey=${privateKey.contentToString()}, " +
                "version=$version, " +
                "parameters=$parameters, " +
                "publicKey=$publicKey" +
                ")"
    }
}
