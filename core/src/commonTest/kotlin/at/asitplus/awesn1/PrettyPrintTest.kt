package at.asitplus.awesn1

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain

val PrettyPrintTest by matrixSuite {
    "pretty print"  {
        val structure = Asn1CustomStructure(
            children = emptyList(),
            tag = 0UL,
            tagClass = TagClass.PRIVATE,
            sortChildren = false,
            shouldBeSorted = false
        )
        structure.prettyPrint() shouldBe """
        PRIVATE 0 (=0xE0), length=0 (=0x00), overallLength=2
        {
        
        }""".trimIndent()
    }

    "pretty prints arbitrary-precision INTEGER values" {
        Asn1Element.parseFromDerHexString("020601A03DDC33B7").prettyPrint() shouldContain "1787744236471"
        Asn1Element.parseFromDerHexString("0209010000000000000000").prettyPrint() shouldContain "18446744073709551616"
        Asn1Primitive(Asn1Element.Tag.INT, byteArrayOf(1) + ByteArray(512)).prettyPrint().also {
            it shouldContain "[truncated, 513 bytes total] 0x"
            it shouldNotContain "Non-compliant"
        }
    }

    "pretty print prefixes hexadecimal values and shows encoded lengths" {
        Asn1Element.parseFromDerHexString("0401AB").prettyPrint().also {
            it shouldContain "tag=4 (=0x04)"
            it shouldContain "length=1 (=0x01)"
            it shouldContain " 0xAB"
        }
        Asn1Element.parseFromDerHexString("048180" + "00".repeat(128)).prettyPrint().also {
            it shouldContain "length=128 (=0x8180)"
        }
    }
}
