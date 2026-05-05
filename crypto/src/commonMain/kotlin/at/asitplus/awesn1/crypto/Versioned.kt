package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1Integer

/**
 *
 * Versioned data classes, as commonly used in ASN.1 schemas.
 *
 * [rawVersion] represents the encoded integer, (semantic) [version] denotes the
 * version commonly referred to when talking about it (as in: a V3 X.509 certificarte has semantic version 3 and a raw version of 2. Other standards will have them align)
 * The integer must fit the valid Int value range (within Int.MIN_VALUE..Int.MAX_VALUE), otherwise a [NumberFormatException] will be thrown.
 */
interface Versioned {
    val rawVersion: Asn1Integer?

    /**
    * Getter may throw but we cannot annotate due to https://youtrack.jetbrains.com/issue/KT-63047/Throws-annotation-on-getter-leads-to-compile-time-error-for-iOS-target
    */
    val version: Int?
}