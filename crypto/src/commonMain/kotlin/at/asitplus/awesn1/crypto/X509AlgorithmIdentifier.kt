// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.WrappedElement
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.decodeFromTlv
import kotlinx.serialization.Serializable
import kotlin.experimental.ExperimentalObjCRefinement
import kotlin.jvm.JvmInline
import kotlin.native.HiddenFromObjC

/**
 * As per [RFC5280](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.1.2):
 *
 * ```
 * AlgorithmIdentifier ::= SEQUENCE {
 *   algorithm   OBJECT IDENTIFIER,
 *   parameters  ANY DEFINED BY algorithm OPTIONAL
 * }
 * ```
 *
 * As a transparent [WrappedElement], an identifier can be added directly to an ASN.1 builder with unary `+`.
 */
@JvmInline
@Serializable
@Suppress("SERIALIZER_TYPE_INCOMPATIBLE")
value class X509AlgorithmIdentifier(override val element: Asn1Sequence) : Identifiable, WrappedElement<Asn1Sequence> {

    /**
     * Convenience constructor for creating an instance of `X509AlgorithmIdentifier`
     * using an `ObjectIdentifier` and a list of `Asn1Element` parameters.
     *
     * The passed [parameters] are unrolled, making construction of the algorithm identifier object work as follows:
     * ```
     * Asn1.Sequence {
     *     +oid
     *     parameters.forEach { +it }
     * }
     * ```
     *
     * @param oid The object identifier representing the algorithm.
     * @param parameters A list of ASN.1 elements representing the algorithm parameters.
     */
    constructor(
        oid: ObjectIdentifier,
        parameters: List<Asn1Element>
    ) : this(Asn1.Sequence {
        +oid
        parameters.forEach { +it }
    })

    init {
        require(element.children.isNotEmpty()) { "AlgorithmIdentifier must not be an empty SEQUENCE" }
        oid //check that oid is present
    }

    //already throws during init, so no throws declaration here
    /**
     * From Swift/Objective-C use the throwing `oid()` accessor (exported as a static `oid(_:)`, since
     * value classes are not bridged as Objective-C types).
     */
    override val oid: ObjectIdentifier
        get() = runRethrowing {
            (element.asSequence().children.firstOrNull() as? Asn1Primitive)?.readOid()
                ?: throw Asn1Exception("AlgorithmIdentifier has no OID: $element")
        }

    /**
     * From Swift/Objective-C use the throwing `parameters()` accessor (exported as a static
     * `parameters(_:)`, since value classes are not bridged as Objective-C types).
     *
     * @throws Asn1Exception if this identifier has more than one parameter element
     */
    @OptIn(ExperimentalObjCRefinement::class)
    @Suppress("WRONG_ANNOTATION_TARGET_WITH_USE_SITE_TARGET")
    @get:Throws(Asn1Exception::class)
    @HiddenFromObjC
    @get:HiddenFromObjC
    val parameters: Asn1Element?
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
