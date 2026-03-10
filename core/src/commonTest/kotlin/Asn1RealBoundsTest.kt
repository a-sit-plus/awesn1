package at.asitplus.awesn1

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.types.shouldBeInstanceOf

val Asn1RealBoundsTest by testSuite {
    "Malformed REAL content fails deterministically" {
        val malformedContents = listOf(
            byteArrayOf(0x80.toByte()), // binary REAL without exponent/mantissa
            byteArrayOf(0x81.toByte(), 0x00), // exponent present, mantissa missing
            byteArrayOf(0x83.toByte()), // extended exponent length marker, missing length octet
            byteArrayOf(0x83.toByte(), 0x01), // missing exponent and mantissa
            byteArrayOf(0x83.toByte(), 0x00, 0x01), // invalid exponent length 0
        )

        malformedContents.forEach { content ->
            shouldThrow<Asn1Exception> {
                Asn1Real.decodeFromAsn1ContentBytes(content)
            }
        }
    }

    "Minimal binary REAL decodes" {
        Asn1Real.decodeFromAsn1ContentBytes(byteArrayOf(0x80.toByte(), 0x00, 0x01))
            .shouldBeInstanceOf<Asn1Real.Finite>()
    }
}
