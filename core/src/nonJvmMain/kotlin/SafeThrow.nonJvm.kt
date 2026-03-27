// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1

import kotlin.coroutines.cancellation.CancellationException

@Suppress("NOTHING_TO_INLINE")
internal actual inline fun Throwable.nonFatalOrThrow(): Throwable = when (this) {
    is CancellationException -> throw this
    else -> this
}
