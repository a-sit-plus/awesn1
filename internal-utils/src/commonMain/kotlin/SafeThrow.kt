// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1

import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.InvocationKind
import kotlin.contracts.contract

expect inline fun Throwable.nonFatalOrThrow(): Throwable

/**
 * Non-fatal-only-catching version of stdlib's [runCatching], returning a [Result] --
 * Re-throws any fatal exceptions, such as `OutOfMemoryError`. Re-implements [Arrow](https://arrow-kt.io)'s
 * [nonFatalOrThrow](https://apidocs.arrow-kt.io/arrow-core/arrow.core/non-fatal-or-throw.html)
 * logic to avoid a dependency on Arrow for a single function.
 */
@OptIn(ExperimentalContracts::class)
@Suppress("NOTHING_TO_INLINE")
inline fun <T> catchingUnwrapped(block: () -> T): Result<T> {
    contract { callsInPlace(block, InvocationKind.AT_MOST_ONCE) }
    return try {
        Result.success(block())
    } catch (e: Throwable) {
        Result.failure(e.nonFatalOrThrow())
    }
}

/** @see catchingUnwrapped */
@OptIn(ExperimentalContracts::class)
@Suppress("NOTHING_TO_INLINE")
inline fun <T, R> T.catchingUnwrapped(block: T.() -> R): Result<R> {
    contract { callsInPlace(block, InvocationKind.AT_MOST_ONCE) }
    return try {
        Result.success(block())
    } catch (e: Throwable) {
        Result.failure(e.nonFatalOrThrow())
    }
}

/**
 * If the underlying [Result] is successful, returns it unchanged.
 * If it failed, and the contained exception is of the specified type, returns it unchanged.
 * Otherwise, wraps the contained exception in the specified type.
 *
 * Usage: `Result.wrapAs(a = ::ThrowableType)`
 */
@OptIn(ExperimentalContracts::class)
inline fun <reified E : Throwable, T> Result<T>.wrapAs(a: (String?, Throwable) -> E): Result<T> {
    contract { callsInPlace(a, InvocationKind.AT_MOST_ONCE) }
    return exceptionOrNull().let { x ->
        if ((x == null) || (x is E)) this@wrapAs
        else Result.failure(a(x.message, x))
    }
}

/** @see wrapAs */
@OptIn(ExperimentalContracts::class)
@Suppress("INVISIBLE_MEMBER", "INVISIBLE_REFERENCE")
@kotlin.internal.LowPriorityInOverloadResolution
inline fun <reified E : Throwable, R> Result<R>.wrapAs(a: (Throwable) -> E): Result<R> {
    contract { callsInPlace(a, InvocationKind.AT_MOST_ONCE) }
    return wrapAs(a = { _, x -> a(x) })
}
