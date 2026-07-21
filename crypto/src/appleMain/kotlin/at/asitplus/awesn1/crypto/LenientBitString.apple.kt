// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1BitString

/**
 * @see LenientBitString.strict
 */
@Throws(IllegalArgumentException::class)
fun LenientBitString.strict(): Asn1BitString = strict
