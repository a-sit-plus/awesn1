package at.asitplus.awesn1

import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.property.Arb
import io.kotest.property.arbitrary.uLong

val TagAssertionTest by matrixSuite {
    compact("Generated") - {
        property("Automated", Arb.uLong(max = ULong.MAX_VALUE - 2uL), iterations = 100000) test { tag ->
            var seq = (Asn1.Sequence { } withImplicitTag tag).asStructure()
            seq.assertTag(tag)
            shouldThrow<Asn1TagMismatchException> {
                seq.assertTag(tag + 1uL)
            }
        }
    }
}
