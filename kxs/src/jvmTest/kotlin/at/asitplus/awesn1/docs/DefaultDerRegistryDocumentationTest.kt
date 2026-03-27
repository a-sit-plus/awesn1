package at.asitplus.awesn1.docs

import at.asitplus.awesn1.Identifiable
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.DefaultDer
import at.asitplus.awesn1.serialization.OidProvider
import at.asitplus.awesn1.serialization.polymorphicByOid
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.modules.SerializersModule

// --8<-- [start:kxs-default-der-registry-definitions]
private interface TutorialDocCmsAttributeValue : Identifiable

@Serializable
private data class TutorialDocCmsContentTypeAttribute(
    val contentType: ObjectIdentifier,
) : TutorialDocCmsAttributeValue, Identifiable by Companion {
    companion object : OidProvider<TutorialDocCmsContentTypeAttribute> {
        override val oid: ObjectIdentifier = ObjectIdentifier("1.2.840.113549.1.9.3")
    }
}

private fun tutorialDocCmsAttributeModule() = SerializersModule {
    polymorphicByOid(
        TutorialDocCmsAttributeValue::class,
        serialName = "TutorialDocCmsAttributeValue",
    ) {
        subtype<TutorialDocCmsContentTypeAttribute>(TutorialDocCmsContentTypeAttribute)
    }
}

@OptIn(ExperimentalSerializationApi::class)
private fun registerCmsAttributeValuesForDefaultDer() {
    DefaultDer.register(tutorialDocCmsAttributeModule())
}
// --8<-- [end:kxs-default-der-registry-definitions]

private fun cmsAttributeRoundTrip(): TutorialDocCmsAttributeValue {
    val codec = DER {
        serializersModule = tutorialDocCmsAttributeModule()
    }
    val value: TutorialDocCmsAttributeValue =
        TutorialDocCmsContentTypeAttribute(ObjectIdentifier("1.2.840.113549.1.7.1"))

    return codec.decodeFromByteArray<TutorialDocCmsAttributeValue>(
        codec.encodeToByteArray<TutorialDocCmsAttributeValue>(value)
    )
}

val DefaultDerRegistryDocumentationTest by testSuite(
    testConfig = DefaultConfiguration
) {
    "Default DER registry docs sample compiles and equivalent module wiring round-trips" {
        ::registerCmsAttributeValuesForDefaultDer.name shouldBe "registerCmsAttributeValuesForDefaultDer"
        cmsAttributeRoundTrip() shouldBe
            TutorialDocCmsContentTypeAttribute(ObjectIdentifier("1.2.840.113549.1.7.1"))
    }
}
