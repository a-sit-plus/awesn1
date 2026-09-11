// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.serialization.internal

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1EncapsulatingOctetString
import at.asitplus.awesn1.Asn1Structure
import kotlinx.serialization.SerializationException

/**
 * Guards structural recursion shared by a root DER encoder/decoder and all of its children.
 */
internal class DerDepthGuard(private var depth: Int = 0) {
    fun enter(maxNestingDepth: Int, serialName: String) {
        depth++
        if (depth > maxNestingDepth) {
            throw SerializationException(
                "ASN.1 nesting depth exceeded the configured maxNestingDepth=$maxNestingDepth while " +
                        "processing '$serialName'. This usually means a recursive @Serializable type is being " +
                        "encoded/decoded at extreme depth; reduce the nesting or raise maxNestingDepth within its " +
                        "supported range."
            )
        }
    }

    fun exit() {
        depth--
    }

    fun ensureElementTreeFits(element: Asn1Element, maxNestingDepth: Int, serialName: String) {
        val pending = ArrayDeque<Pair<Asn1Element, Int>>()
        pending += element to depth
        while (pending.isNotEmpty()) {
            val (current, parentDepth) = pending.removeFirst()
            val children = when (current) {
                is Asn1Structure -> current.children
                is Asn1EncapsulatingOctetString -> current.children
                else -> continue
            }
            val currentDepth = parentDepth + 1
            if (currentDepth > maxNestingDepth) {
                throw SerializationException(
                    "ASN.1 nesting depth exceeded the configured maxNestingDepth=$maxNestingDepth while " +
                            "processing '$serialName'."
                )
            }
            children.forEach { pending += it to currentDepth }
        }
    }
}
