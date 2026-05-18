// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.decodeFromTlv
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Deprecated("Use X509AlgorithmIdentifier instead", ReplaceWith("X509AlgorithmIdentifier"))
typealias SignatureAlgorithmIdentifier = X509AlgorithmIdentifier

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
value class X509AlgorithmIdentifier(val element: Asn1Sequence) : Identifiable {
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

    /**
     * Getter may throw but we cannot annotate due to https://youtrack.jetbrains.com/issue/KT-63047/Throws-annotation-on-getter-leads-to-compile-time-error-for-iOS-target
     */
    override val oid: ObjectIdentifier
        get() = (element.asSequence().children.firstOrNull() as? Asn1Primitive)?.readOid()
            ?: throw Asn1Exception("AlgorithmIdentifier is empty")

    /**
     * Getter may throw but we cannot annotate due to https://youtrack.jetbrains.com/issue/KT-63047/Throws-annotation-on-getter-leads-to-compile-time-error-for-iOS-target
     */
    val parameters: Asn1Element?
        get() = when (element.children.size) {
            1 -> null
            2 -> element.children[1]
            else -> throw Asn1Exception("AlgorithmIdentifier has ${element.children.size} children")
        }

    /**
     * Parses [parameters] as RSASSA-PSS parameters if this identifier uses the `id-RSASSA-PSS` OID.
     *
     * This helper models [RFC 4055, section 3.1](https://www.rfc-editor.org/rfc/rfc4055.html#section-3.1) without
     * making [X509AlgorithmIdentifier] itself enforce algorithm-specific parameter schemas during generic DER parsing.
     *
     * @return `null` if this algorithm is nor RSA_SSA_PSS
     *
     * @throws Asn1Exception if this algorothm is RSA_SSA_PSS has no parameters, or the parameter element is
     * not a valid `RSASSA-PSS-params` SEQUENCE.
     *
     * Getter may throw but we cannot annotate due to https://youtrack.jetbrains.com/issue/KT-63047/Throws-annotation-on-getter-leads-to-compile-time-error-for-iOS-target
     */
    val rsaSsaPssParams: RsaSsaPssParams?
        get() = runWrappingAs(a = ::Asn1Exception) {
            if (oid != RsaSsaPssParams.RSA_SSA_PSS_OID) {
                return null
            }
            DER.decodeFromTlv<RsaSsaPssParams>(
                parameters?.asSequence() ?: throw Asn1Exception("RSASSA-PSS AlgorithmIdentifier has no parameters")
            )
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
