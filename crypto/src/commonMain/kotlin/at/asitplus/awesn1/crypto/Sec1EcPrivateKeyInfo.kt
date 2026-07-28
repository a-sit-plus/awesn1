// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1OctetString
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.PemLabelSpec
import at.asitplus.awesn1.WithPemLabel
import at.asitplus.awesn1.runRethrowing
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Der
import at.asitplus.awesn1.serialization.ExplicitlyTagged
import at.asitplus.awesn1.serialization.decodeFromDer
import at.asitplus.awesn1.serialization.decodeFromTlv
import at.asitplus.awesn1.serialization.getValue
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
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
@ConsistentCopyVisibility
@Serializable
//CTOR internal for testing
data class Sec1EcPrivateKeyInfo internal constructor(
    val version: Version,
    val privateKey: ByteArray,
    @Asn1Tag(tagNumber = 0u)
    private val taggedParameters: ExplicitlyTagged<ObjectIdentifier>? = null,
    @Asn1Tag(tagNumber = 1u)
    private val taggedPublicKey: ExplicitlyTagged<Asn1BitString>? = null,
) : WithPemLabel {

    constructor(
        version: Version = Version.V1,
        privateKey: ByteArray,
        parameters: ObjectIdentifier?,
        publicKey: Asn1BitString?,
    ) : this(
        version = Version.V1,
        privateKey = privateKey,
        taggedParameters = parameters?.let(::ExplicitlyTagged),
        taggedPublicKey = publicKey?.let(::ExplicitlyTagged),
    )
    override val pemLabel: String get() = PEM_LABEL

    init {
        taggedPublicKey?.value?.let {
            if (it.numPaddingBits != 0.toByte()) {
                throw Asn1Exception("Public key value must not have padding bits")
            }
        }
    }

    val parameters: ObjectIdentifier? by taggedParameters

    val publicKey: Asn1BitString? by taggedPublicKey

    override fun equals(other: Any?): Boolean =
        other is Sec1EcPrivateKeyInfo &&
                version == other.version &&
                privateKey.contentEquals(other.privateKey) &&
                taggedParameters == other.taggedParameters &&
                taggedPublicKey == other.taggedPublicKey

    override fun hashCode(): Int {
        var result = version.hashCode()
        result = 31 * result + privateKey.contentHashCode()
        result = 31 * result + taggedParameters.hashCode()
        result = 31 * result + taggedPublicKey.hashCode()
        return result
    }

    override fun toString(): String {
        return "Sec1EcPrivateKeyInfo(" +
                "rawVersion=$version, " +
                "privateKey=${privateKey.contentToString()}, " +
                "version=$version, " +
                "parameters=$parameters, " +
                "publicKey=$publicKey" +
                ")"
    }

    companion object : PemLabelSpec<Sec1EcPrivateKeyInfo> {
        const val PEM_LABEL = "EC PRIVATE KEY"
        override val canonicalPemLabel: String get() = PEM_LABEL

        private val EC_PUBLIC_KEY_OID = ObjectIdentifier("1.2.840.10045.2.1")

        operator fun Pkcs8PrivateKeyInfo.Companion.invoke(
            privateKey: Sec1EcPrivateKeyInfo, curveOid: ObjectIdentifier?,
            attributes: Set<Asn1Element>? = null, der: Der = DER
        ) = runRethrowing {
            Pkcs8PrivateKeyInfo(
                version = Pkcs8PrivateKeyInfo.Version.V1,
                privateKeyAlgorithm = X509AlgorithmIdentifier(
                    EC_PUBLIC_KEY_OID,
                    curveOid?.encodeToTlv(),
                ),
                privateKey = Asn1OctetString(der.encodeToByteArray(privateKey)),
                attributes = attributes,
            )
        }

        fun of(privateKeyInfo: Pkcs8PrivateKeyInfo, der: Der = DER) = runRethrowing {
            require(privateKeyInfo.algorithmOid == EC_PUBLIC_KEY_OID)
                { "Pkcs8PrivateKeyInfo is not an RSA private key" }
            val curveOid = privateKeyInfo.algorithmParameters?.let { der.decodeFromTlv<ObjectIdentifier>(it) }
            // TODO: is this curve oid somehow relevant?
            der.decodeFromTlv<Sec1EcPrivateKeyInfo>(
                privateKeyInfo.privateKey.asEncapsulatingOctetString().element)

        }

    }

    /**
     * | Encoded Version | Semantic Version |
     * |:---------------:|:----------------:|
     * | 1               | V1                |
     */

    @Serializable(with = Version.Serializer::class)
    enum class Version {
        V1;

        object Serializer : KSerializer<Version> {
            override val descriptor: SerialDescriptor =
                PrimitiveSerialDescriptor("Sec1EcPrivateKeyInfo.Version", PrimitiveKind.INT)

            override fun serialize(encoder: Encoder, value: Version) {
                encoder.encodeInt(when(value) {
                    V1 -> 1
                })
            }

            override fun deserialize(decoder: Decoder): Version {
                when (val intValue = decoder.decodeInt()) {
                    1 -> return V1
                    else -> throw IllegalArgumentException("Invalid version: $intValue")
                }
            }
        }
    }
}
