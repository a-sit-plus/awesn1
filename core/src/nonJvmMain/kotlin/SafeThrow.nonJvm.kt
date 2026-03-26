// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1

import kotlin.coroutines.cancellation.CancellationException

@Suppress("NOTHING_TO_INLINE")
actual inline fun Throwable.ifNotFatal(): Throwable = (this as? CancellationException)?.let { throw it } ?: this