// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.catchingUnwrapped

/**
 *
 * Versioned data classes, as commonly used in ASN.1 schemas.
 *
 * [rawVersion] represents the encoded integer, (semantic) [version] denotes the
 * version commonly referred to when talking about it (as in: a V3 X.509 certificare has semantic version 3 and a
 * raw version of 2 and a v1 certificate may encode its raw version as absent, while other standards may have raw and semantic version align).
 * Hence, [version] is never null, because even an absent [rawVersion] will correspond to some semantic version.
 * The integer must fit the valid Int value range (within [Int.MIN_VALUE]..[Int.MAX_VALUE]), otherwise a [NumberFormatException] will be thrown.
 */
interface Versioned {
    /** [rawVersion] represents the encoded integer as represented in ASN.1, whose absence may have semantics attached other than not being present */
    val rawVersion: Asn1Integer?

    /**
     * This is the (semantic) [version]. It denotes the
     * version commonly referred to when talking about it (as in: a V3 X.509 certificate has semantic version 3 and a
     * raw version of 2 and a v1 certificate may encode its raw version as absent, while other standards may have raw and semantic version align).
     * Hence, [version] is never null, because even an absent [rawVersion] will correspond to some semantic version.
     * The raw version integer must fit the valid Int value range (within [Int.MIN_VALUE]..[Int.MAX_VALUE]), otherwise a [NumberFormatException] will be thrown.
     * Hence, this property shall be implemented through a lazy delegate.
     *
     * Getter may throw but we cannot annotate due to https://youtrack.jetbrains.com/issue/KT-63047/Throws-annotation-on-getter-leads-to-compile-time-error-for-iOS-target
     */
    val version: Int
}

/**
 * Similar to [toIntOrNull]:
 * Parses [rawVersion] an Int number or returns null if it is not a valid representation of an Int.
 * [rawVersion] must fit the valid Int value range (within [Int.MIN_VALUE]..[Int.MAX_VALUE]), otherwise null is returned.
 *
 * @return the semantic version as an `Int` if successful, or `null` if an exception occurs.
 */
fun Versioned.versionOrNull(): Int? = catchingUnwrapped { version }.getOrNull()