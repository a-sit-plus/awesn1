// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

/**
 * RFC 5280 `Name`. The currently defined CHOICE has exactly one alternative, an `RDNSequence`.
 */
typealias X500Name = List<X500RelativeDistinguishedName>
