// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1EncapsulatingOctetString
import at.asitplus.awesn1.Asn1Encodable
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1PrimitiveOctetString
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.Asn1TagMismatchException
import at.asitplus.awesn1.Identifiable
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.decodeRethrowing
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.Asn1.Bool
import at.asitplus.awesn1.encoding.decodeToBoolean
import at.asitplus.awesn1.readOid
import at.asitplus.awesn1.serialization.Asn1Serializable
import kotlinx.serialization.Serializable

@Serializable(with = X509CertificateExtension.Companion::class)
open class X509CertificateExtension @Throws(Asn1Exception::class) protected constructor(
    override val oid: ObjectIdentifier,
    val value: Asn1Element,
    private val rawCritical: Asn1Element? = null,
) : Asn1Encodable<Asn1Sequence>, Identifiable {

    val critical: Boolean
        get() = rawCritical?.asPrimitive()?.decodeToBoolean() ?: false

    init {
        rawCritical?.let {
            if (it.tag != Asn1Element.Tag.BOOL) {
                throw Asn1TagMismatchException(Asn1Element.Tag.BOOL, it.tag)
            }
        }
        if (value.tag != Asn1Element.Tag.OCTET_STRING) {
            throw Asn1TagMismatchException(Asn1Element.Tag.OCTET_STRING, value.tag)
        }
    }

    constructor(
        oid: ObjectIdentifier,
        critical: Boolean = false,
        value: Asn1EncapsulatingOctetString
    ) : this(oid, value, if (critical) Bool(true) else null)

    constructor(
        oid: ObjectIdentifier,
        critical: Boolean = false,
        value: Asn1PrimitiveOctetString
    ) : this(oid, value, if (critical) Bool(true) else null)

    override fun encodeToTlv() = Asn1.Sequence {
        +oid
        rawCritical?.let { +it }
        +value
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as X509CertificateExtension

        if (oid != other.oid) return false
        if (rawCritical != other.rawCritical) return false
        if (value != other.value) return false

        return true
    }

    override fun hashCode(): Int {
        var result = oid.hashCode()
        result = 31 * result + (rawCritical?.hashCode() ?: 0)
        result = 31 * result + value.hashCode()
        return result
    }

    companion object : Asn1Serializable<Asn1Sequence, X509CertificateExtension> {
        override val leadingTags = setOf(Asn1Element.Tag.SEQUENCE)

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): X509CertificateExtension = src.decodeRethrowing {
            val id = next().asPrimitive().readOid()
            var critical: Asn1Element? = null
            val maybeCritical = peek()!!
            if (maybeCritical.tag == Asn1Element.Tag.BOOL) {
                critical = next()
            }

            val value = next()
            X509CertificateExtension(id, value, critical)
        }
    }
}
