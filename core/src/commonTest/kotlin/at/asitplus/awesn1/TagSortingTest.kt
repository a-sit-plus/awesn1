package at.asitplus.awesn1

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.comparables.shouldBeGreaterThan
import io.kotest.matchers.comparables.shouldBeLessThan
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.uLong

val TagSortingTest by matrixSuite {

    compact("Automated") - {
        val sortedClasses =
            listOf(TagClass.UNIVERSAL, TagClass.APPLICATION, TagClass.CONTEXT_SPECIFIC, TagClass.PRIVATE)
        property("a", Arb.uLong(), iterations = 1000) - { a ->

            test("class ordering") {
                val tagAAPP = Asn1Element.Tag(
                    a,
                    constructed = false,
                    tagClass = TagClass.APPLICATION
                )
                val tagACTX = Asn1Element.Tag(
                    a,
                    constructed = false,
                    tagClass = TagClass.CONTEXT_SPECIFIC
                )
                val tagAP = Asn1Element.Tag(
                    a,
                    constructed = false,
                    tagClass = TagClass.PRIVATE
                )

                val tagAC = if (a > 0uL) Asn1Element.Tag(
                    a,
                    constructed = true,
                    tagClass = TagClass.UNIVERSAL
                ) else null

                if (a > 0uL) {
                    val tagA = Asn1Element.Tag(
                        a,
                        constructed = false,
                        tagClass = TagClass.UNIVERSAL
                    )
                    tagA.compareTo(tagAC!!) shouldBe 0

                    tagA shouldBeLessThan tagAAPP
                }
                tagAAPP shouldBeLessThan tagACTX
                tagACTX shouldBeLessThan tagAP
                tagAC?.let {
                    it shouldBeLessThan tagAAPP
                    it shouldBeLessThan tagACTX
                    it shouldBeLessThan tagAP
                }
            }

            if (a > 0uL) {
                val tagA = Asn1Element.Tag(
                    a,
                    constructed = false,
                    tagClass = TagClass.UNIVERSAL
                )
                property("b", Arb.uLong(min = 1uL), iterations = 1000) test { b ->
                    val tagB = Asn1Element.Tag(
                        b,
                        constructed = false,
                        tagClass = TagClass.UNIVERSAL
                    )

                    if (a < b) {
                        tagA shouldBeLessThan tagB
                    } else if (a > b) {
                        tagA shouldBeGreaterThan tagB
                    }

                    sortedClasses.forEachIndexed { i, left ->
                        sortedClasses.drop(i + 1).forEach { right ->
                            Asn1Element.Tag(a, constructed = false, tagClass = left) shouldBeLessThan
                                    Asn1Element.Tag(b, constructed = false, tagClass = right)
                        }
                    }
                }
            }
        }
    }
}
