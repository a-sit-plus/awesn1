// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1

open class Asn1Exception(message: String?, cause: Throwable?) : Throwable(message, cause) {
    constructor(message: String) : this(message, null)
    constructor(throwable: Throwable) : this(null, throwable)
}

class Asn1TagMismatchException(
    val expected: Asn1Element.Tag,
    val actual: Asn1Element.Tag,
    detailedMessage: String? = null
) :
    Asn1Exception((detailedMessage?.let { "$it " } ?: "") + "Expected tag $expected, is: $actual")

class Asn1StructuralException(message: String, cause: Throwable? = null) : Asn1Exception(message, cause)

class Asn1OidException(message: String, val oid: ObjectIdentifier) : Asn1Exception(message)

/**
 * Runs [block] inside [catchingUnwrapped] and encapsulates any thrown exception in an [Asn1Exception] unless it already is one
 */
@PublishedApi
@Throws(Asn1Exception::class)
internal inline fun <R> runRethrowing(block: () -> R) =
    runWrappingAs(::Asn1Exception, block)

/**
 * Decodes this ASN.1 structure using the provided [decoder] lambda, rethrowing any caught exception
 * as an [Asn1Exception].
 * This is a wrapper around [Asn1Structure.decodeAs] that ensures exceptions thrown during decoding are
 * consistently rethrown as [Asn1Exception], using the [runRethrowing] utility.
 */
inline fun <R> Asn1Structure.decodeRethrowing(
    requireFullConsumption: Boolean = true,
    decoder: Asn1Structure.Iterator.() -> R
) = runRethrowing { this@decodeRethrowing.decodeAs(requireFullConsumption, decoder) }

class ImplementationError(message: String? = null) :
    Throwable("$message\nThis is an implementation error. Please report this bug at https://github.com/a-sit-plus/awesn1/issues/new/")
