// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.WrappedElement
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
 * @see RsaSsaPssParams.of
 */
@JvmInline
@Serializable
@Suppress("SERIALIZER_TYPE_INCOMPATIBLE")
value class X509AlgorithmIdentifier(override val element: Asn1Sequence) : Identifiable, WrappedElement<Asn1Sequence> {

    /**
     * Convenience constructor for creating an instance of `X509AlgorithmIdentifier`
     * using an `ObjectIdentifier` and a list of `Asn1Element` parameters.
     *
     * **Note that passing `null` as [parameters] is different from passing [Asn1Null] as [parameters].**
     * Passing `null` omits the second member from the sequence entirely. (e.g., ECDSA)
     * Passing [Asn1Null] encodes ASN.1 NULL as the second member of the sequence. (e.g., RSA/PKCS1)
     *
     * @param oid The object identifier representing the algorithm.
     * @param parameters The algorithm parameters element, if any.
     */
    constructor(
        oid: ObjectIdentifier,
        parameters: Asn1Element?
    ) : this(Asn1.Sequence {
        +oid
        parameters?.let { +it }
    })

    @Suppress("INVISIBLE_MEMBER", "INVISIBLE_REFERENCE")
    @kotlin.internal.LowPriorityInOverloadResolution
    constructor(oid: ObjectIdentifier, parameters: WrappedElement<out Asn1Element>?) : this(oid, parameters?.element)

    @Deprecated(level = DeprecationLevel.WARNING, message = "parameters can only have 0 or 1 elements, use nullable ctor",
        replaceWith = ReplaceWith("X509AlgorithmIdentifier(oid, parameters.singleOrNull())"))
    constructor(oid: ObjectIdentifier, parameters: List<Asn1Element>) : this(oid, parameters.singleOrNull())

    init {
        val _ = oid //check that oid is present
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
            else -> throw Asn1Exception("AlgorithmIdentifier has ${element.children.size} (> 2) children")
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
