// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(at.asitplus.awesn1.InternalAwesn1Api::class)

package at.asitplus.awesn1.hardening

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.InternalAwesn1Api
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.encoding.decodeFromDer
import at.asitplus.awesn1.encoding.internal.readFullyToAsn1Elements
import at.asitplus.awesn1.wrapInUnsafeSource
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

/**
 * Constructs a DER-encoded OID TLV containing a subidentifier made up of
 * `numContinuationBytes` continuation octets (each `0x80`) followed by a
 * single terminator (`0x7F`).
 *
 * Example: numContinuationBytes=3 produces TLV `06 06 2B 80 80 80 7F`
 * (OID 1.3 with one tail subidentifier encoded across 4 base-128 octets).
 */
private fun makeOidWithGiantSubidentifier(numContinuationBytes: Int): ByteArray {
    val firstTwoArcs = byteArrayOf(0x2B.toByte())
    val giantArc = ByteArray(1 + numContinuationBytes) {
        if (it < numContinuationBytes) 0x80.toByte() else 0x7F.toByte()
    }
    val content = firstTwoArcs + giantArc
    val lengthOctets = when {
        content.size < 0x80 -> byteArrayOf(content.size.toByte())
        else -> byteArrayOf(
            (0x80 or ((content.size shr 8) and 0xFF)).toByte(),
            (content.size and 0xFF).toByte()
        )
    }
    return byteArrayOf(0x06) + lengthOctets + content
}

val UnboundedParsingTest by matrixSuite {


    "OID with giant subidentifier causes excessive memory allocation" - {
        "16_000_000 continuation bytes should be rejected or capped" {
            shouldThrow<Throwable> {
                val tlv = makeOidWithGiantSubidentifier(16_000_000)
                ObjectIdentifier.decodeFromDer(tlv)
            }.message shouldBe "Unsupported length >2^8 (was: 36 length bytes)"
        }

        "moderate: 500_000 continuation bytes should be rejected or capped" {
            shouldThrow<Throwable> {
                val tlv = makeOidWithGiantSubidentifier(500_000)
                ObjectIdentifier.decodeFromDer(tlv)
            }.message shouldBe "Unsupported length >2^8 (was: 33 length bytes)"
        }

        "50_000 continuation bytes should be rejected or capped" {
            shouldThrow<Throwable> {
                val tlv = makeOidWithGiantSubidentifier(50_000)
                ObjectIdentifier.decodeFromDer(tlv)
            }.message shouldBe "Unsupported length >2^8 (was: 67 length bytes)"
        }
    }
}
