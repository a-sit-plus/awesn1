package at.asitplus.awesn1

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestCompartment
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

val KnownOIDTests by testSuite(compartment = { TestCompartment.Sequential }) {


    "Own descriptions" {

        @OptIn(ExperimentalUuidApi::class)
        val expressionistOID = ObjectIdentifier(Uuid.random())

        KnownOIDs[expressionistOID].shouldBeNull()
        KnownOIDs[expressionistOID] = "Edvard Munch"
        KnownOIDs[expressionistOID] shouldBe "Edvard Munch"

    }
}