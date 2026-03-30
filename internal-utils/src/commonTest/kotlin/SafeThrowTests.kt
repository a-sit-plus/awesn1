package at.asitplus.awesn1

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.coroutines.CancellationException

val SafeThrowTests by testSuite {
    "Critical failures are not swallowed" {
        shouldThrow<CancellationException> { catchingUnwrapped { throw CancellationException(null, null) } }
    }
    "Other failures are swallowed" {
        shouldNotThrowAny { catchingUnwrapped { throw IllegalArgumentException() } }
    }
    "Wrapping works" {
        val x = RuntimeException("foo")
        shouldThrow<IllegalArgumentException> {
            runWrappingAs(a=::IllegalArgumentException) { throw x }
        }.run {
            message shouldBe "foo"
            cause shouldBe x
        }
    }
    "We don't double wrap" {
        val x = IllegalArgumentException("foo")
        shouldThrow<IllegalArgumentException> {
            runWrappingAs(a=::IllegalArgumentException) { throw x }
        }.run {
            message shouldBe "foo"
            cause shouldBe null
        }
    }
}