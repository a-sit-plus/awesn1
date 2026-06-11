package at.asitplus.awesn1

import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.decodeToEnum
import at.asitplus.awesn1.encoding.decodeToEnumOrdinal
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe

enum class TestEnum {
    ONE, TWO, THREE
}

val EnumTest by matrixSuite {

    listOf(Long.MIN_VALUE, Long.MAX_VALUE, -1L, Int.MAX_VALUE.toLong() + 1L, Int.MIN_VALUE.toLong() - 1L)
        .asData(name = "Values beyond valid Kotlin enum ordinals should work") test { ordinal -> Asn1.Enumerated(ordinal).decodeToEnumOrdinal() shouldBe ordinal }

    data("encoding should produce correct ordinals", TestEnum.entries) test { entry ->
        val automagically = Asn1.Enumerated(entry)
        automagically shouldBe Asn1.Enumerated(entry.ordinal)
        //check correct tag
        automagically.derEncoded shouldBe byteArrayOf(0xa, 1, entry.ordinal.toByte())

        automagically.decodeToEnumOrdinal() shouldBe entry.ordinal
        val decoded: TestEnum = automagically.decodeToEnum()
        decoded shouldBe entry
    }
}
