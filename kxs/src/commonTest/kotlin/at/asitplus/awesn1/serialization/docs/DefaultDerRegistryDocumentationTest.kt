package at.asitplus.awesn1.docs

import at.asitplus.awesn1.Identifiable
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.OidProvider
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

// --8<-- [start:kxs-default-der-registry-definitions]
interface CustomAttribute : Identifiable

@Serializable
data class ConcreteCustomAttribute(
    val contentType: ObjectIdentifier,
) : CustomAttribute, Identifiable by Companion {
    companion object : OidProvider<ConcreteCustomAttribute> {
        override val oid: ObjectIdentifier = ObjectIdentifier("1.2.840.113549.1.9.3")
    }
}
// --8<-- [end:kxs-default-der-registry-definitions]

val DefaultDerRegistryDocumentationTest by testSuite {
    "Default DER registry docs sample compiles and equivalent module wiring round-trips" {

        //setup happens one per test invocation. this cannot work otherwise. hence, check ModuleTestSession

        // --8<-- [start:kxs-default-der-registry-usage]
        val value: CustomAttribute =
            ConcreteCustomAttribute(ObjectIdentifier("1.2.840.113549.1.7.1"))
        DER.decodeFromByteArray<CustomAttribute>(
            DER.encodeToByteArray<CustomAttribute>(value)
        ) shouldBe ConcreteCustomAttribute(ObjectIdentifier("1.2.840.113549.1.7.1"))
        // --8<-- [end:kxs-default-der-registry-usage]
    }
}
