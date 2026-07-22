@file:OptIn(ExperimentalObjCName::class)
// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1BitString
import kotlin.experimental.ExperimentalObjCName

/**
 * @see LenientBitString.strict
 */
@Throws(IllegalArgumentException::class)
@ObjCName("strict")
fun __apple_workaround_LenientBitString_strict(it: LenientBitString) = it.strict
