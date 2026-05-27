package at.asitplus.awesn1.hardening

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.encoding.Asn1
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe

object DerLimitFixtures {
    val singleElement = Asn1.Sequence {
        +Asn1.Int(1)
    }
    val singleElementDer = singleElement.derEncoded
    val singleElementHex = singleElement.toDerHexString()
    val singleElementLimit = singleElementDer.size.toLong()
    val singleElementBelowLimit = singleElementLimit - 1

    val singleInteger = Asn1.Int(1)
    val singleIntegerDer = singleInteger.derEncoded
    val singleIntegerHex = singleInteger.toDerHexString()
    val singleIntegerLimit = singleIntegerDer.size.toLong()
    val singleIntegerBelowLimit = singleIntegerLimit - 1
    val singleIntegerValue = Asn1Integer(1)

    val multiElementDer = byteArrayOf(
        0x02, 0x01, 0x01,
        0x02, 0x01, 0x02,
    )
    val multiElementLimit = multiElementDer.size.toLong()
    val multiElementBelowLimit = multiElementLimit - 1
    val multiElements = listOf<Asn1Element>(
        Asn1.Int(1),
        Asn1.Int(2),
    )
}

inline fun <T> assertExactLimitSucceedsAndBelowLimitThrows(
    exactLimit: Long,
    belowLimit: Long,
    expected: T,
    crossinline decode: (Long) -> T,
) {
    withClue("OK") {
        decode(exactLimit) shouldBe expected
    }
    withClue("below limit") {
        shouldThrow<Throwable> {
            decode(belowLimit)
        }
    }
}

inline fun assertExactLimitSucceedsAndBelowLimitReturnsNull(
    exactLimit: Long,
    belowLimit: Long,
    expected: Asn1Integer,
    crossinline decode: (Long) -> Asn1Integer?,
) {
    withClue("OK") {
        decode(exactLimit) shouldBe expected
    }
    withClue("null") {
        decode(belowLimit) shouldBe null
    }
}
