// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(ExperimentalObjCName::class)

package at.asitplus.awesn1.crypto

import kotlin.experimental.ExperimentalObjCName

/**
 * @see RsaSsaPssParams.effectiveTrailerField
 */
@Throws(NumberFormatException::class)
@ObjCName("effectiveTrailerField")
@Deprecated(
    message = "Objective-C export only",
    level = DeprecationLevel.HIDDEN
)
fun __apple_workaround_RsaSsaPssParams_effectiveTrailerField(it: RsaSsaPssParams) = it.effectiveTrailerField

/**
 * @see RsaSsaPssParams.effectiveSaltLength
 */
@Throws(NumberFormatException::class)
@ObjCName("effectiveSaltLength")
@Deprecated(
    message = "Objective-C export only",
    level = DeprecationLevel.HIDDEN
)
fun __apple_workaround_RsaSsaPssParams_effectiveSaltLength(it: RsaSsaPssParams) = it.effectiveSaltLength
