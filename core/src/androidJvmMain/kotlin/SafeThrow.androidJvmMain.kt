package at.asitplus.awesn1


import kotlin.coroutines.cancellation.CancellationException
@Suppress("NOTHING_TO_INLINE")
actual inline fun Throwable.safeThrow(): Throwable = when (this) {
    is VirtualMachineError, is ThreadDeath, is InterruptedException, is LinkageError, is CancellationException -> throw this
    else -> this
}