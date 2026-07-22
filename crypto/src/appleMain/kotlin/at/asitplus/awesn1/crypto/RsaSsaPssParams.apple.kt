@file:OptIn(ExperimentalObjCName::class)
// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import kotlin.experimental.ExperimentalObjCName

/**
 * @see RsaSsaPssParams.effectiveTrailerField
 */
@Throws(NumberFormatException::class)
@ObjCName("effectiveTrailerField")
fun __apple_workaround_RsaSsaPssParams_effectiveTrailerField(it: RsaSsaPssParams) = it.effectiveTrailerField

/**
 * @see RsaSsaPssParams.effectiveSaltLength
 */
@Throws(NumberFormatException::class)
@ObjCName("effectiveSaltLength")
fun __apple_workaround_RsaSsaPssParams_effectiveSaltLength(it: RsaSsaPssParams) = it.effectiveSaltLength
