// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.Identifiable
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.readOid
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@JvmInline
@Serializable
value class AlgorithmIdentifier(val element: Asn1Element) : Identifiable {
    constructor(
        oid: ObjectIdentifier,
        parameters: List<Asn1Element> = emptyList(),
    ) : this(Asn1.Sequence {
        +oid
        parameters.forEach { +it }
    })

    override val oid: ObjectIdentifier
        get() = (element.asSequence().children.firstOrNull() as? Asn1Primitive)?.readOid()
            ?: throw Asn1Exception("AlgorithmIdentifier is empty")

    val parameters: List<Asn1Element>
        get() = element.asSequence().children.drop(1)

    override fun toString(): String = "SignatureAlgorithmIdentifier($oid)"
}
