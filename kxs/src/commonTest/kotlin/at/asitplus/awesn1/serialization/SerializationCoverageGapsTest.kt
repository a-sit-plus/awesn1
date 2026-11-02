package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.parse
import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.matrixConfig
import de.infix.testBalloon.framework.core.invocation
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.modules.SerializersModule
import kotlin.jvm.JvmInline

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestCoverageGaps by matrixSuite(
    matrixConfig { execution= ExecutionMode.Sequential }
) {
    "Asn1Tag INFER defaults class to context-specific while inferring constructed" {
        val value = InferTagOnPrimitive(1)
        val element = Asn1Element.parse(
            DER.encodeToByteArray(value)
        ).asStructure().children.single()

        // Current behavior: INFER still resolves to CONTEXT_SPECIFIC for class/tag class.
        element.tag.tagClass shouldBe TagClass.CONTEXT_SPECIFIC
        element.tag.isConstructed shouldBe false
        element.tag.tagValue shouldBe 9UL
        DER.decodeFromByteArray<InferTagOnPrimitive>(
            DER.encodeToByteArray(value)
        ) shouldBe value
    }

    listOf("3003450107", "3003c50107", "3003050107").asData(
        name = "Asn1Tag INFER rejects foreign wire tag classes",
        nameFn = { it },
    ) test { encoded ->
        shouldThrow<SerializationException> {
            DER.decodeFromByteArray<InferTagOnPrimitive>(encoded.hexToByteArray())
        }.cause.shouldBeInstanceOf<Asn1TagMismatchException>()
    }

    "Asn1Tag constructed=INFER keeps constructed=true for class-level structures" {
        val value = InferConstructedOnClass(7)
        val element = Asn1Element.parse(DER.encodeToByteArray(value))

        element.tag.tagClass shouldBe TagClass.CONTEXT_SPECIFIC
        element.tag.isConstructed shouldBe true
        element.tag.tagValue shouldBe 3UL
        DER.decodeFromByteArray<InferConstructedOnClass>(DER.encodeToByteArray(value)) shouldBe value
    }

    "Asn1Explicit requires an explicit context-specific constructed tag" {
        shouldThrow<SerializationException> {
            DER.encodeToByteArray(ExplicitNoTag(ExplicitlyTagged(5)))
        }
        shouldThrow<SerializationException> {
            DER.encodeToByteArray(ExplicitlyTagged(5))
        }
        shouldThrow<SerializationException> {
            DER.encodeToByteArray(ExplicitWrongConstructed(ExplicitlyTagged(5)))
        }
    }

    "ExplicitlyTagged delegate exposes typed value" {
        val wrapped = ExplicitlyTagged(5)
        val value by wrapped

        value shouldBe 5
    }

    "Nullable ExplicitlyTagged delegate exposes nullable typed value" {
        val wrapped: ExplicitlyTagged<Asn1Integer>? = ExplicitlyTagged(Asn1Integer(5u))
        val value by wrapped

        value shouldBe Asn1Integer(5u)

        val missing: ExplicitlyTagged<Asn1Integer>? = null
        val nullValue by missing

        nullValue shouldBe null
    }

    "Asn1BitString on non-ByteArray targets is currently ignored (no shape change)" {
        val value = InvalidBitStringTarget(1)
        val encoded = DER.encodeToByteArray(value)
        encoded.toHexString() shouldBe "3003020101"
        DER.decodeFromByteArray<InvalidBitStringTarget>(encoded) shouldBe value
    }

    "Open polymorphism by tag rejects duplicate leading-tag mappings" {
        shouldThrow<IllegalArgumentException> {
            DER {
                serializersModule = SerializersModule {
                    polymorphicByTag(DuplicateTagBase::class, serialName = "DuplicateTagBase") {
                        subtype<DuplicateTagA>()
                        subtype<DuplicateTagB>()
                    }
                }
            }
        }
    }

    "Open polymorphism by OID rejects duplicate OID mappings" {
        shouldThrow<IllegalArgumentException> {
            DER {
                serializersModule = SerializersModule {
                    polymorphicByOid(DuplicateOidBase::class, serialName = "DuplicateOidBase") {
                        subtype<DuplicateOidA>(DuplicateOidA)
                        subtype<DuplicateOidB>(DuplicateOidB)
                    }
                }
            }
        }
    }

    "Open polymorphism by OID rejects duplicate catchAll mappings" {
        shouldThrow<IllegalArgumentException> {
            DER {
                serializersModule = SerializersModule {
                    polymorphicByOid(DuplicateOidBase::class, serialName = "DuplicateOidBase") {
                        subtype<DuplicateOidA>(DuplicateOidA)
                        catchAll<DuplicateOidCatchAll>()
                        catchAll<DuplicateOidCatchAllOther>()
                    }
                }
            }
        }
    }

    "Open polymorphism by OID catchAll does not shadow exact subtype matches" {
        val der = DER {
            serializersModule = SerializersModule {
                polymorphicByOid(DuplicateOidBase::class, serialName = "DuplicateOidBase") {
                    subtype<DuplicateOidA>(DuplicateOidA)
                    catchAll<DuplicateOidCatchAll>()
                }
            }
        }

        der.decodeFromByteArray<DuplicateOidBase>(
            der.encodeToByteArray<DuplicateOidBase>(DuplicateOidA(1))
        ) shouldBe DuplicateOidA(1)
    }

    "encodeDefaults=false and explicitNulls=true compose as expected" {
        val der = DER {
            encodeDefaults = false
            explicitNulls = true
        }

        val withRequiredNull = CombinedFlagsModel(requiredNullable = null)
        val encoded = der.encodeToByteArray(withRequiredNull)

        // Only requiredNullable is emitted as ASN.1 NULL:
        // - defaultedNullable is omitted due to encodeDefaults=false
        // - trailingDefault is omitted due to encodeDefaults=false
        encoded.toHexString() shouldBe "30020500"
        der.decodeFromByteArray<CombinedFlagsModel>(encoded) shouldBe withRequiredNull
    }
}

@Serializable
private data class InferTagOnPrimitive(
    @Asn1Tag(
        tagNumber = 9u,
        tagClass = Asn1Tag.Class.INFER,
        constructed = Asn1Tag.ConstructedBit.INFER,
    ) val value: Int,
)

@Serializable
@Asn1Tag(
    tagNumber = 3u,
    tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC,
    constructed = Asn1Tag.ConstructedBit.INFER,
)
private data class InferConstructedOnClass(
    val value: Int,
)

@Serializable
private data class ExplicitNoTag(
    val wrapped: ExplicitlyTagged<Int>,
)

@Serializable
private data class ExplicitWrongClass(
    @Asn1Tag(
        tagNumber = 0u,
        tagClass = Asn1Tag.Class.UNIVERSAL,
        constructed = Asn1Tag.ConstructedBit.CONSTRUCTED,
    ) val wrapped: ExplicitlyTagged<Int>,
)

@Serializable
private data class ExplicitWrongConstructed(
    @Asn1Tag(
        tagNumber = 0u,
        tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC,
        constructed = Asn1Tag.ConstructedBit.PRIMITIVE,
    ) val wrapped: ExplicitlyTagged<Int>,
)

@Serializable
private data class InvalidBitStringTarget(
    @Asn1BitString val value: Int,
)

private interface DuplicateTagBase

@Serializable
@JvmInline
private value class DuplicateTagA(val value: Int) : DuplicateTagBase

@Serializable
@JvmInline
private value class DuplicateTagB(val value: Int) : DuplicateTagBase

private interface DuplicateOidBase : Identifiable

@Serializable
private data class DuplicateOidA(val value: Int) : DuplicateOidBase, Identifiable by Companion {
    companion object : OidProvider<DuplicateOidA> {
        override val oid: ObjectIdentifier = ObjectIdentifier("1.2.3.4.5")
    }
}

@Serializable
private data class DuplicateOidB(val value: String) : DuplicateOidBase, Identifiable by Companion {
    companion object : OidProvider<DuplicateOidB> {
        override val oid: ObjectIdentifier = ObjectIdentifier("1.2.3.4.5")
    }
}

@Serializable
private data class DuplicateOidCatchAll(
    override val oid: ObjectIdentifier,
    val value: String,
) : DuplicateOidBase

@Serializable
private data class DuplicateOidCatchAllOther(
    override val oid: ObjectIdentifier,
    val value: Int,
) : DuplicateOidBase

@Serializable
private data class CombinedFlagsModel(
    val requiredNullable: Int?,
    val defaultedNullable: Int? = null,
    val trailingDefault: Boolean = true,
)
