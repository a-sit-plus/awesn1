// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.readOid
import at.asitplus.awesn1.runRethrowing
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Der

sealed class Sec1EcPublicKeyInfo(val curveOid: ObjectIdentifier, val x: ByteArray) {
    class Uncompressed(curveOid: ObjectIdentifier, x: ByteArray, val y: ByteArray) : Sec1EcPublicKeyInfo(curveOid, x) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Uncompressed) return false
            return curveOid == other.curveOid && x.contentEquals(other.x) && y.contentEquals(other.y)
        }

        override fun hashCode() = 31 * (31 * curveOid.hashCode() + x.contentHashCode()) + y.contentHashCode()
    }

    class Compressed(curveOid: ObjectIdentifier, x: ByteArray, val positiveY: Boolean) : Sec1EcPublicKeyInfo(curveOid, x) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Compressed) return false
            return curveOid == other.curveOid && x.contentEquals(other.x) && positiveY == other.positiveY
        }

        override fun hashCode() = 31 * (31 * curveOid.hashCode() + x.contentHashCode()) + positiveY.hashCode()
    }

    companion object {
        private val EC_PUBLIC_KEY_OID = ObjectIdentifier("1.2.840.10045.2.1")
        const val UNCOMPRESSED_PREFIX = 0x04.toByte()
        const val COMPRESSED_PLUS_PREFIX = 0x03.toByte()
        const val COMPRESSED_MINUS_PREFIX = 0x02.toByte()
        fun of(publicKeyInfo: SubjectPublicKeyInfo, der: Der = DER) = runRethrowing {
            require(publicKeyInfo.algorithmOid == EC_PUBLIC_KEY_OID)
                { "SubjectPublicKeyInfo is not an ECDSA public key" }
            val curveOid = publicKeyInfo.algorithmParameters?.asPrimitive()?.readOid() ?:
                throw IllegalArgumentException("ECDSA SubjectPublicKeyInfo must not contain NULL params")
            require(publicKeyInfo.subjectPublicKey.numPaddingBits == 0.toByte())
                { "ECDSA subjectPublicKey must only have full octets" }
            val contentBytes = publicKeyInfo.subjectPublicKey.bitCarryingBytes
            when (val firstByte = contentBytes[0]) {
                UNCOMPRESSED_PREFIX -> {
                    require(contentBytes.size % 2 == 1) // leading byte + even number
                        { "ECDSA subjectPublicKey must have an even number of point octets" }
                    val midpoint = (contentBytes.size + 1) / 2 // = (size-1)/2+1
                    Uncompressed(
                        curveOid = curveOid,
                        x = contentBytes.copyOfRange(1, midpoint),
                        y = contentBytes.copyOfRange(midpoint, contentBytes.size))
                }
                COMPRESSED_PLUS_PREFIX, COMPRESSED_MINUS_PREFIX -> {
                    Compressed(
                        curveOid = curveOid,
                        x = contentBytes.copyOfRange(1, contentBytes.size),
                        positiveY = (firstByte == COMPRESSED_PLUS_PREFIX))
                }
                else -> throw Asn1Exception("Unknown ECDSA prefix byte $firstByte")
            }
        }

        operator fun SubjectPublicKeyInfo.Companion.invoke(publicKey: Sec1EcPublicKeyInfo) = runRethrowing {
            SubjectPublicKeyInfo(
                X509AlgorithmIdentifier(EC_PUBLIC_KEY_OID, publicKey.curveOid.encodeToTlv()),
                when (publicKey) {
                    is Compressed -> when (publicKey.positiveY) {
                        true -> byteArrayOf(COMPRESSED_PLUS_PREFIX, *publicKey.x)
                        false -> byteArrayOf(COMPRESSED_MINUS_PREFIX, *publicKey.x)
                    }
                    is Uncompressed -> byteArrayOf(UNCOMPRESSED_PREFIX, *publicKey.x, *publicKey.y)
                }.let(::Asn1BitString)
            )
        }

        fun SubjectPublicKeyInfo.Companion.ec(curveOid: ObjectIdentifier, ansiX963Key: ByteArray): SubjectPublicKeyInfo = runRethrowing {
            when (val firstByte = ansiX963Key[0]) {
                UNCOMPRESSED_PREFIX -> require(ansiX963Key.size % 2 == 1)
                    { "ECDSA subjectPublicKey must have an even number of point octets" }
                COMPRESSED_PLUS_PREFIX, COMPRESSED_MINUS_PREFIX -> {}
                else -> throw Asn1Exception("Unknown ECDSA prefix byte $firstByte")
            }
            return SubjectPublicKeyInfo(
                algorithmIdentifier = X509AlgorithmIdentifier(EC_PUBLIC_KEY_OID, curveOid.encodeToTlv()),
                subjectPublicKey = Asn1BitString(ansiX963Key))
        }
    }
}