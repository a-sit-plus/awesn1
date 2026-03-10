package at.asitplus.awesn1

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe

val PrettyPrintTest by testSuite {
    "pretty print"  {
        val structure = Asn1CustomStructure(
            children = emptyList(),
            tag = 0UL,
            tagClass = TagClass.PRIVATE,
            sortChildren = false,
            shouldBeSorted = false
        )
        structure.prettyPrint() shouldBe """
        PRIVATE 0 (=E0), length=0, overallLength=2
        {
        
        }""".trimIndent()
    }
}