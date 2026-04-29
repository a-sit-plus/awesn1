// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.Asn1
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

/**
 * As per [RFC5280](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.1.2):
 *
 * ```
 * AlgorithmIdentifier ::= SEQUENCE {
 *   algorithm   OBJECT IDENTIFIER,
 *   parameters  ANY DEFINED BY algorithm OPTIONAL
 * }
 * ```
 */
@JvmInline
@Serializable
@Suppress("SERIALIZER_TYPE_INCOMPATIBLE")
value class AlgorithmIdentifier(val element: Asn1Sequence) : Identifiable {
    constructor(
        oid: ObjectIdentifier,
        parameters: Asn1Element? = null
    ) : this(Asn1.Sequence {
        +oid
        parameters?.let { +it }
    })

    constructor(
        oid: ObjectIdentifier,
        parameters: List<Asn1Element>
    ) : this(Asn1.Sequence {
        +oid
        parameters.forEach { +it }
    })

    init {
        //would be nice to assert exactly 1 or 2 children, but reality is a b****.
    }

    override val oid: ObjectIdentifier
        //cannot annotate with throws due to Kotlin bug
        get() = (element.asSequence().children.firstOrNull() as? Asn1Primitive)?.readOid()
            ?: throw Asn1Exception("AlgorithmIdentifier is empty")

    val parameters: Asn1Element?
        //cannot annotate with throws due to Kotlin bug
        get() = when (element.children.size) {
            1 -> null
            2 -> element.children[1]
            else -> throw Asn1Exception("AlgorithmIdentifier has ${element.children.size} children")
        }

    override fun toString(): String {
        return catchingUnwrapped {
            "AlgorithmIdentifier(" +
                    "oid=$oid, " +
                    "parameters=$parameters, " +
                    "(raw=$element)" +
                    ")"
        }.getOrElse { "Invalid AlgorithmIdentifier(raw=$element)" }
    }

}
