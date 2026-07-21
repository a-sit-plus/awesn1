// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

/**
 * @see RsaSsaPssParams.effectiveTrailerField
 */
@Throws(NumberFormatException::class)
fun RsaSsaPssParams.effectiveTrailerField(): Int = effectiveTrailerField

/**
 * @see RsaSsaPssParams.effectiveSaltLength
 */
@Throws(NumberFormatException::class)
fun RsaSsaPssParams.effectiveSaltLength(): Int = effectiveSaltLength