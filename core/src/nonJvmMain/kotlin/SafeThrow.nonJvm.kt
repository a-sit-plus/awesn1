package at.asitplus.awesn1

import kotlin.coroutines.cancellation.CancellationException

@Suppress("NOTHING_TO_INLINE")
actual inline fun Throwable.safeThrow(): Throwable = (this as? CancellationException)?.let { throw it } ?: this