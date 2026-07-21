// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

/**
 * RFC 5280 `Name`. The currently defined CHOICE has exactly one alternative, an `RDNSequence`.
 */
@JvmInline
@Serializable
value class X500Name(private val value: List<X500RelativeDistinguishedName>) : List<X500RelativeDistinguishedName> by value {
    constructor(single: X500RelativeDistinguishedName) : this(listOf(single))
}

