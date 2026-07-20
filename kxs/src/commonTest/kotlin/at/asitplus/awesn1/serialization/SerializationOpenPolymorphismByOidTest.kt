package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.Asn1Structure
import at.asitplus.awesn1.Identifiable
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.readOid
import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.matrixConfig
import de.infix.testBalloon.framework.core.invocation
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.modules.SerializersModule


@OptIn(ExperimentalStdlibApi::class)
val SerializationTestOpenPolymorphismByOid by matrixSuite(
    matrixConfig { execution= ExecutionMode.Sequential }
) {
    "Open-polymorphic OID dispatch round-trips with registered subtypes" {
        val der = derWithOpenByOid(includeBool = false)
        val intValue: OpenByOid = OpenByOidInt(value = 7)
        val strValue: OpenByOid = OpenByOidString(value = "hello")

        der.decodeFromByteArray<OpenByOid>(
            der.encodeToByteArray(intValue)
        ) shouldBe intValue
        der.decodeFromByteArray<OpenByOid>(
            der.encodeToByteArray(strValue)
        ) shouldBe strValue
    }

    "Additional OID subtype can be enabled by extending the DER serializers module" {
        val strictDer = derWithOpenByOid(includeBool = false)
        val extendedDer = derWithOpenByOid(includeBool = true)
        val boolValue: OpenByOid = OpenByOidBool(value = true)

        shouldThrow<SerializationException> {
            strictDer.encodeToByteArray(boolValue)
        }.message.shouldContain("No registered open-polymorphic subtype")

        val encoded = extendedDer.encodeToByteArray(boolValue)
        extendedDer.decodeFromByteArray<OpenByOid>(encoded) shouldBe boolValue

        shouldThrow<SerializationException> {
            strictDer.decodeFromByteArray<OpenByOid>(encoded)
        }.message.shouldContain("for OID")
    }

    "Missing OID discriminator fails decode" {
        val der = derWithOpenByOid(includeBool = false)
        val encodedNoOid = der.encodeToByteArray(NoOidEnvelope.serializer(), NoOidEnvelope(value = 1))
        shouldThrow<SerializationException> {
            der.decodeFromByteArray<OpenByOid>(encodedNoOid)
        }.message.shouldContain("Could not extract discriminator OID")
    }

    "Unknown OID decodes to catchAll and preserves the OID" {
        val der = derWithOpenByOid(includeBool = false, includeCatchAll = true)
        val raw: OpenByOid = OpenByOidRaw(
            oid = ObjectIdentifier("1.2.840.113549.1.9.7"),
            value = "challenge",
        )

        val decoded = der.decodeFromByteArray<OpenByOid>(der.encodeToByteArray(raw))
        decoded.shouldBeInstanceOf<OpenByOidRaw>() shouldBe raw
    }

    "Known OID still resolves to specialized subtype when catchAll is present" {
        val der = derWithOpenByOid(includeBool = false, includeCatchAll = true)
        val value: OpenByOid = OpenByOidInt(value = 7)

        der.decodeFromByteArray<OpenByOid>(der.encodeToByteArray(value)) shouldBe value
    }

    "catchAll instance encodes and round-trips with its own OID" {
        val der = derWithOpenByOid(includeBool = false, includeCatchAll = true)
        val value: OpenByOid = OpenByOidRaw(
            oid = ObjectIdentifier("2.16.840.1.101.3.4.2.1"),
            value = "digest",
        )

        der.decodeFromByteArray<OpenByOid>(der.encodeToByteArray(value)) shouldBe value
    }

    "catchAll can be the only OID registration" {
        val der = DER {
            serializersModule = SerializersModule {
                polymorphicByOid(OpenByOid::class, serialName = "CatchAllOnly") {
                    catchAll<OpenByOidRaw>()
                }
            }
        }
        val value: OpenByOid = OpenByOidRaw(
            oid = ObjectIdentifier("1.2.840.113549.1.9.7"),
            value = "challenge",
        )

        der.decodeFromByteArray<OpenByOid>(der.encodeToByteArray(value)) shouldBe value
    }

    "open subtype inherits its wrapper tag without affecting subtype field tags" {
        val der = DER {
            serializersModule = SerializersModule {
                polymorphicByOid(OpenByOid::class, serialName = "TaggedOpenByOid") {
                    subtype<OpenByOidWithTaggedValue>(OpenByOidWithTaggedValue)
                }
            }
        }
        val value: TaggedOpenByOidChoice = TaggedOpenByOidChoice.Open(
            OpenByOidWithTaggedValue(ExplicitlyTagged(7))
        )

        val encoded = der.encodeToByteArray(value)
        val outer = Asn1Element.parse(encoded).shouldBeInstanceOf<Asn1Structure>()
        outer.tag.tagValue shouldBe 9uL
        outer.children.last().tag.tagValue shouldBe 0uL
        der.decodeFromByteArray<TaggedOpenByOidChoice>(encoded) shouldBe value
    }

    "catchAll encodes its discriminator OID exactly once (no injected duplicate)" {
        // Regression: the catch-all carries its OID as its own first field, so the framework must NOT
        // also inject a discriminator OID — otherwise the OID appears twice and the bytes are not the
        // canonical single-OID structure (which would, e.g., break standard X.509 extension DER).
        val der = derWithOpenByOid(includeBool = false, includeCatchAll = true)
        val value: OpenByOid = OpenByOidRaw(oid = ObjectIdentifier("1.2.840.113549.1.9.7"), value = "challenge")

        val encoded = der.encodeToByteArray(value)
        val children = Asn1Element.parse(encoded).asSequence().children
        children.count { it.tag == Asn1Element.Tag.OID } shouldBe 1
        (children.first() as Asn1Primitive).readOid() shouldBe ObjectIdentifier("1.2.840.113549.1.9.7")
    }
}

interface OpenByOid : Identifiable

@Serializable
data class OpenByOidInt(
    val value: Int,
) : OpenByOid, Identifiable by Companion {

    companion object : OidProvider<OpenByOidInt> {

        override val oid: ObjectIdentifier
            get() = ObjectIdentifier("1.2.840.113549.1.1.1")
    }
}

@Serializable
data class OpenByOidString(
    val value: String,
) : OpenByOid, Identifiable by Companion {
    companion object : OidProvider<OpenByOidString> {
        override val oid: ObjectIdentifier
            get() = ObjectIdentifier("1.2.840.10045.2.1")
    }
}

@Serializable
data class OpenByOidBool(
    val value: Boolean,
) : OpenByOid, Identifiable by Companion {
    companion object : OidProvider<OpenByOidBool> {
        override val oid: ObjectIdentifier get() = ObjectIdentifier("1.3.101.110")
    }
}

@Serializable
data class OpenByOidRaw(
    override val oid: ObjectIdentifier,
    val value: String,
) : OpenByOid

@Serializable
data class OpenByOidWithTaggedValue(
    @Asn1Tag(tagNumber = 0u, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    val taggedValue: ExplicitlyTagged<Int>,
) : OpenByOid, Identifiable by Companion {
    companion object : OidProvider<OpenByOidWithTaggedValue> {
        override val oid: ObjectIdentifier = ObjectIdentifier("1.3.6.1.4.1.55555.1")
    }
}

@Serializable
sealed interface TaggedOpenByOidChoice {
    @Serializable
    @JvmInline
    @Asn1Tag(tagNumber = 9u, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    value class Open(val value: OpenByOid) : TaggedOpenByOidChoice
}

@Serializable
data class NoOidEnvelope(
    val value: Int,
)

interface OpenByNestedOid

@Serializable
data class NestedAlgorithmIdentifier(
    val oid: ObjectIdentifier,
)

@Serializable
data class OpenByNestedOidA(
    val algorithm: NestedAlgorithmIdentifier = NestedAlgorithmIdentifier(OpenByOidInt.oid),
    val payload: Int,
) : OpenByNestedOid

@Serializable
data class OpenByNestedOidB(
    val algorithm: NestedAlgorithmIdentifier = NestedAlgorithmIdentifier(OpenByOidString.oid),
    val payload: String,
) : OpenByNestedOid

private fun derWithOpenByOid(includeBool: Boolean, includeCatchAll: Boolean = false) = DER {
    serializersModule = SerializersModule {
        polymorphicByOid(OpenByOid::class, serialName = "OpenByOid") {
            subtype<OpenByOidInt>(OpenByOidInt)
            subtype<OpenByOidString>(OpenByOidString)
            if (includeBool) {
                subtype<OpenByOidBool>(OpenByOidBool)
            }
            if (includeCatchAll) {
                catchAll<OpenByOidRaw>()
            }
        }
    }
}
