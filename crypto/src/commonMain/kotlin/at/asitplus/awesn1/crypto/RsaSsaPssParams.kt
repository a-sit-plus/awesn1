// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.runRethrowing
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Der
import at.asitplus.awesn1.serialization.ExplicitlyTagged
import at.asitplus.awesn1.serialization.decodeFromTlv
import at.asitplus.awesn1.serialization.encodeToTlv
import at.asitplus.awesn1.serialization.getValue
import at.asitplus.awesn1.toInt
import kotlinx.serialization.Serializable
import kotlin.experimental.ExperimentalObjCRefinement
import kotlin.native.HiddenFromObjC

@Serializable
sealed interface RsaParams

/**
 * This is just NULL, but we need a common interface for RSA
 */
@Serializable
@Asn1Tag(tagNumber = 5uL, tagClass = Asn1Tag.Class.UNIVERSAL, constructed = Asn1Tag.ConstructedBit.PRIMITIVE)
object RsaPkcs1PaddingParams : RsaParams

/**
 * RSASSA-PSS parameters as specified by
 * [RFC 4055, section 3.1](https://www.rfc-editor.org/rfc/rfc4055.html#section-3.1):
 *
 * ```
 * RSASSA-PSS-params ::= SEQUENCE {
 *   hashAlgorithm      [0] HashAlgorithm      DEFAULT sha1Identifier,
 *   maskGenAlgorithm   [1] MaskGenAlgorithm   DEFAULT mgf1SHA1Identifier,
 *   saltLength         [2] INTEGER            DEFAULT 20,
 *   trailerField       [3] TrailerField       DEFAULT trailerFieldBC
 * }
 * ```
 *
 * The encoded fields are optional because the ASN.1 type defines defaults. The `effective*` accessors expose the
 * RFC defaults without forcing callers to reject unsupported parameter combinations while parsing an outer
 * [X509AlgorithmIdentifier].
 */
@ConsistentCopyVisibility
@Serializable
//CTOR internal for testing
data class RsaSsaPssParams internal constructor(
    @Asn1Tag(tagNumber = 0u)
    private val taggedHashAlgorithm: ExplicitlyTagged<X509AlgorithmIdentifier>? = null,
    @Asn1Tag(tagNumber = 1u)
    private val taggedMaskGenAlgorithm: ExplicitlyTagged<X509AlgorithmIdentifier>? = null,
    @Asn1Tag(tagNumber = 2u)
    private val taggedSaltLength: ExplicitlyTagged<Asn1Integer>? = null,
    @Asn1Tag(tagNumber = 3u)
    private val taggedTrailerField: ExplicitlyTagged<Asn1Integer>? = null,
) : RsaParams {
    constructor(
        hashAlgorithm: X509AlgorithmIdentifier = SHA1_IDENTIFIER,
        maskGenAlgorithm: X509AlgorithmIdentifier = MGF1_SHA1_IDENTIFIER,
        saltLength: Int = DEFAULT_SALT_LENGTH,
        trailerField: Int = DEFAULT_TRAILER_FIELD,
    ) : this(
        taggedHashAlgorithm = hashAlgorithm.takeIf { it != SHA1_IDENTIFIER }?.let(::ExplicitlyTagged),
        taggedMaskGenAlgorithm = maskGenAlgorithm.takeIf { it != MGF1_SHA1_IDENTIFIER }?.let(::ExplicitlyTagged),
        taggedSaltLength = saltLength.takeIf { it != DEFAULT_SALT_LENGTH }?.let { ExplicitlyTagged(Asn1Integer(it)) },
        taggedTrailerField = trailerField.takeIf { it != DEFAULT_TRAILER_FIELD }?.let { ExplicitlyTagged(Asn1Integer(it)) },
    )

    val hashAlgorithm: X509AlgorithmIdentifier? by taggedHashAlgorithm

    val maskGenAlgorithm: X509AlgorithmIdentifier? by taggedMaskGenAlgorithm

    val saltLength: Asn1Integer? by taggedSaltLength

    val trailerField: Asn1Integer? by taggedTrailerField

    val effectiveHashAlgorithm: X509AlgorithmIdentifier get() = hashAlgorithm ?: SHA1_IDENTIFIER

    val effectiveMaskGenAlgorithm: X509AlgorithmIdentifier get() = maskGenAlgorithm ?: MGF1_SHA1_IDENTIFIER


    /**
     * Hidden from Objective-C because a throwing getter cannot be bridged (see
     * [KT-63047](https://youtrack.jetbrains.com/issue/KT-63047)); from Swift/Objective-C use the
     * throwing `effectiveSaltLength()` accessor instead.
     *
     * @throws NumberFormatException if the salt length is not a valid integer
     */
    @OptIn(ExperimentalObjCRefinement::class)
    @Suppress("WRONG_ANNOTATION_TARGET_WITH_USE_SITE_TARGET")
    @get:Throws(NumberFormatException::class)
    @HiddenFromObjC
    @get:HiddenFromObjC
    val effectiveSaltLength: Int by lazy { saltLength?.toInt() ?: DEFAULT_SALT_LENGTH }

    /**
     * Hidden from Objective-C because a throwing getter cannot be bridged (see
     * [KT-63047](https://youtrack.jetbrains.com/issue/KT-63047)); from Swift/Objective-C use the
     * throwing `effectiveTrailerField()` accessor instead.
     *
     * @throws NumberFormatException if the trailer field is not a valid integer
     */
    @OptIn(ExperimentalObjCRefinement::class)
    @Suppress("WRONG_ANNOTATION_TARGET_WITH_USE_SITE_TARGET")
    @get:Throws(NumberFormatException::class)
    @HiddenFromObjC
    @get:HiddenFromObjC
    val effectiveTrailerField: Int by lazy { trailerField?.toInt() ?: DEFAULT_TRAILER_FIELD }

    companion object {
        val RSA_SSA_PSS_OID = ObjectIdentifier("1.2.840.113549.1.1.10")
        val MGF1_OID = ObjectIdentifier("1.2.840.113549.1.1.8")
        val SHA1_OID = ObjectIdentifier("1.3.14.3.2.26")

        const val DEFAULT_SALT_LENGTH = 20
        const val DEFAULT_TRAILER_FIELD = 1

        val SHA1_IDENTIFIER = X509AlgorithmIdentifier(SHA1_OID, listOf(Asn1.Null()))
        val MGF1_SHA1_IDENTIFIER = X509AlgorithmIdentifier(MGF1_OID, listOf(SHA1_IDENTIFIER.element))

        fun X509AlgorithmIdentifier.Companion.of(params: RsaSsaPssParams, der: Der = DER) = runRethrowing {
            X509AlgorithmIdentifier(
                RSA_SSA_PSS_OID,
                listOf(der.encodeToTlv(params))
            )
        }

        @Deprecated(level = DeprecationLevel.WARNING, message = "prefer of(), which can take a `Der` object",
            replaceWith = ReplaceWith("RsaSsaPssParams.of(this)"))
        val X509AlgorithmIdentifier.rsaSsaPssParams get() = RsaSsaPssParams.of(this)
        /**
         * Asserts that this identifier uses the `id-RSASSA-PSS` OID,
         * then parses [parameters] as RSASSA-PSS parameters.
         *
         * This helper models [RFC 4055, section 3.1](https://www.rfc-editor.org/rfc/rfc4055.html#section-3.1).
         *
         * @throws Asn1Exception if this algorithm is RSA_SSA_PSS has no parameters, or the parameter element is
         * not a valid `RSASSA-PSS-params` SEQUENCE.
         */
        fun of(algorithmIdentifier: X509AlgorithmIdentifier, der: Der = DER): RsaSsaPssParams = runRethrowing {
            require(algorithmIdentifier.oid == RSA_SSA_PSS_OID)
            der.decodeFromTlv<RsaSsaPssParams>(
                algorithmIdentifier.parameters?.asSequence() ?:
                    throw Asn1Exception("RSASSA-PSS AlgorithmIdentifier has no parameters")
            )
        }

    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is RsaSsaPssParams) return false

        if (taggedHashAlgorithm != other.taggedHashAlgorithm) return false
        if (taggedMaskGenAlgorithm != other.taggedMaskGenAlgorithm) return false
        if (taggedSaltLength != other.taggedSaltLength) return false
        if (taggedTrailerField != other.taggedTrailerField) return false

        return true
    }

    override fun hashCode(): Int {
        var result = taggedHashAlgorithm?.hashCode() ?: 0
        result = 31 * result + (taggedMaskGenAlgorithm?.hashCode() ?: 0)
        result = 31 * result + (taggedSaltLength?.hashCode() ?: 0)
        result = 31 * result + (taggedTrailerField?.hashCode() ?: 0)
        return result
    }

    override fun toString(): String {
        return "RsaSsaPssParams(" +
                "effectiveHashAlgorithm=$effectiveHashAlgorithm, " +
                "effectiveMaskGenAlgorithm=$effectiveMaskGenAlgorithm, " +
                "effectiveSaltLength=$effectiveSaltLength, " +
                "effectiveTrailerField=$effectiveTrailerField, " +
                "hashAlgorithm=$hashAlgorithm, " +
                "maskGenAlgorithm=$maskGenAlgorithm, " +
                "saltLength=$saltLength, " +
                "trailerField=$trailerField" +
                ")"
    }
}