// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(kotlinx.serialization.ExperimentalSerializationApi::class, ExperimentalStdlibApi::class)

package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.encodeToByteArray
import kotlin.jvm.JvmInline

@Serializable
private data class DsInner(val x: Int)

@Serializable
private data class DsConstTaggedNullable(
    @Asn1Tag(tagNumber = 0uL, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    val inner: DsInner?,
)

val null_roundtrip_constructed_tag by matrixSuite {
    val der = DER { explicitNulls = true }
    "A non-null constructed-tagged value round-trips" {
        val value = DsConstTaggedNullable(DsInner(7))
        der.roundTrip(value) shouldBe value
    }
    "A null constructed-tagged value round-trips" {
        val value = DsConstTaggedNullable(null)
        der.roundTrip(value) shouldBe value
    }
}

@Serializable
private data class DsItemModel(
    @Asn1Tag(tagNumber = 1uL) val items: List<Int>?,
    @Asn1Tag(tagNumber = 2uL) val trail: Int,
)

val null_sentinel_data_swallow by matrixSuite {
    val der = DER { explicitNulls = true }
    "Null and populated lists retain their distinct wire encodings" {
        der.encodeToByteArray(DsItemModel(null, 9)).toHexString() shouldBe "30058100820109"
        der.encodeToByteArray(DsItemModel(listOf(7), 9)).toHexString() shouldBe "3008a103020107820109"
    }
    "A primitive tagged list carrying content is rejected" {
        shouldThrow<SerializationException> {
            der.decodeFromDer<DsItemModel>("30088103010203820109".hexToByteArray())
        }
    }
}

@Serializable
@JvmInline
private value class GlWrappedInt(val v: Int)

@Serializable
private data class GlWrappedIntHolder(@Asn1Tag(tagNumber = 5uL) val x: GlWrappedInt?)

val inline_nullable_null_sentinel_undecodable by matrixSuite {
    for (explicitNulls in listOf(false, true)) {
        val der = DER { this.explicitNulls = explicitNulls }
        "A nullable inline property decodes null with explicitNulls=$explicitNulls" {
            val wire = if (explicitNulls) "30020500" else "3000"
            der.decodeFromDer<GlWrappedIntHolder>(wire.hexToByteArray()) shouldBe GlWrappedIntHolder(null)
        }

        "A nullable inline property round-trips null with explicitNulls=$explicitNulls" {
            der.roundTrip(GlWrappedIntHolder(null)) shouldBe GlWrappedIntHolder(null)
        }

        for ((number, wire) in listOf(0 to "3003850100", 1 to "3003850101")) {
            "A nullable inline property decodes $number with explicitNulls=$explicitNulls" {
                der.decodeFromDer<GlWrappedIntHolder>(wire.hexToByteArray()) shouldBe GlWrappedIntHolder(GlWrappedInt(number))
            }

            "A nullable inline property round-trips $number with explicitNulls=$explicitNulls" {
                val value = GlWrappedIntHolder(GlWrappedInt(number))
                der.roundTrip(value) shouldBe value
            }
        }
    }
}

@Serializable
private data class GlRawNullableHolder(val raw: Asn1Element? = null)

val nullable_raw_element_null_sentinel_collision by matrixSuite {
    "A non-NULL raw element round-trips" {
        val value = GlRawNullableHolder(Asn1.Int(1))
        DER.roundTrip(value) shouldBe value
    }
    "A raw NULL value round-trips when property nulls are omitted" {
        val value = GlRawNullableHolder(Asn1.Null())
        DER.roundTrip(value) shouldBe value
    }
    "Explicit nulls reject a raw NULL value colliding with the property sentinel" {
        shouldThrow<SerializationException> {
            DER { explicitNulls = true }.encodeToByteArray(GlRawNullableHolder(Asn1.Null()))
        }
    }
}

@Serializable
private data class GlPrimitiveNullSentinel(
    @Asn1Tag(tagNumber = 0uL, constructed = Asn1Tag.ConstructedBit.PRIMITIVE) val a: String?,
    val b: Int,
)

@Serializable
private data class GlListNullSentinel(
    @Asn1Tag(tagNumber = 0uL, constructed = Asn1Tag.ConstructedBit.PRIMITIVE) val a: List<Int>?,
    val b: Int,
)

val nullsentinel_emptycoll_primitive_tag by matrixSuite {
    val der = DER { explicitNulls = true }
    "An ambiguous primitive String null sentinel is rejected" {
        shouldThrow<SerializationException> { der.encodeToByteArray(GlPrimitiveNullSentinel(null, 5)) }
    }
    "A primitive-tagged null list has different bytes from an empty list" {
        der.encodeToByteArray(GlListNullSentinel(null, 5)).toHexString() shouldNotBe
            der.encodeToByteArray(GlListNullSentinel(emptyList(), 5)).toHexString()
    }
}

@Serializable
private data class GlHostNullableInt(val wrapped: OctetStringEncapsulated<Int?>)

val octetwrapper_null_payload_undecodable by matrixSuite {
    "A non-null encapsulated payload round-trips" {
        val value = GlHostNullableInt(OctetStringEncapsulated(7))
        DER.roundTrip(value) shouldBe value
    }
    "A null encapsulated payload round-trips" {
        val value = GlHostNullableInt(OctetStringEncapsulated(null))
        DER.roundTrip(value) shouldBe value
    }
}

private enum class NullOptionalMode { OFF, ON }

@Serializable
private data class GlJustEnum(val e: NullOptionalMode? = null)

val nullable_enum_presence_tag_int_vs_enumerated by matrixSuite {
    val value = GlJustEnum(NullOptionalMode.OFF)
    val encoded = DER.encodeToByteArray(value)
    "Explicit nulls accept a populated nullable ENUMERATED property" {
        DER { explicitNulls = true }.decodeFromDer<GlJustEnum>(encoded) shouldBe value
    }
    "Omitted nulls accept the same populated ENUMERATED property" {
        DER.decodeFromDer<GlJustEnum>(encoded) shouldBe value
    }
}

@Serializable
private data class GlTailNonNull(val id: Int, val exts: LenientSet<Int>)

@Serializable
private data class GlTailLenient(val id: Int, val exts: LenientSet<Int>? = null)

val setdescriptor_nullable_setof_owntag_reject by matrixSuite {
    val encoded = DER.encodeToByteArray(GlTailNonNull(1, LenientSet(linkedSetOf(2, 1))))
    "A required SET OF property decodes" {
        DER.decodeFromDer<GlTailNonNull>(encoded).id shouldBe 1
    }
    "The same SET OF bytes decode into a nullable property" {
        DER.decodeFromDer<GlTailLenient>(encoded).exts shouldBe LenientSet(linkedSetOf(1, 2))
    }
}

@Serializable
private data class NullOptionalInner(val a: Int)

@Serializable
private data class NullOptionalModelNullableOpt(
    val first: NullOptionalInner,
    val opt: NullOptionalInner? = null,
    @Asn1Tag(tagNumber = 1uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    val last: NullOptionalInner?,
)

@Serializable
private data class NullOptionalModelDefaultedOpt(
    val first: NullOptionalInner,
    val opt: NullOptionalInner = NullOptionalInner(7),
    @Asn1Tag(tagNumber = 1uL, tagClass = Asn1Tag.Class.CONTEXT_SPECIFIC, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    val last: NullOptionalInner?,
)

val gate_certifies_undecodable_defaulted_optional_layouts by matrixSuite {
    val encoded = "300a3003020105a103020109".hexToByteArray()
    "An omitted nullable middle property decodes" {
        DER.decodeFromDer<NullOptionalModelNullableOpt>(encoded) shouldBe NullOptionalModelNullableOpt(NullOptionalInner(5), null, NullOptionalInner(9))
    }
    "An omitted defaulted middle property retains its default" {
        DER.decodeFromDer<NullOptionalModelDefaultedOpt>(encoded) shouldBe NullOptionalModelDefaultedOpt(NullOptionalInner(5), NullOptionalInner(7), NullOptionalInner(9))
    }
}

@Serializable
@SerialName("GlShared")
private data class GlDisambiguated(
    @Asn1Tag(tagNumber = 0uL) val opt: Int? = null,
    @Asn1Tag(tagNumber = 1uL) val req: Int? = null,
)

@Serializable
@SerialName("GlShared")
private data class GlAmbiguous(val opt: Int? = null, val req: Int? = null)

@Serializable
private data class GlRootBoth(val a: GlDisambiguated, val b: GlAmbiguous)

val layoutplan_structural_equals_dedupe_bypasses_ambiguity_guard by matrixSuite {
    "An ambiguous layout is rejected on its own" {
        shouldThrow<SerializationException> { DER.decodeFromDer<GlAmbiguous>("3003020108".hexToByteArray()) }
    }
    "An ambiguous layout is still checked after a structurally equal tagged sibling" {
        shouldThrow<SerializationException> {
            DER.decodeFromDer<GlRootBoth>("300d30068001058101063003020108".hexToByteArray())
        }
    }
}

@Serializable
private data class GlNullableDefaultedCollision(
    @Asn1Tag(tagNumber = 5uL) val a: Int? = null,
    @Asn1Tag(tagNumber = 5uL) val b: Int? = null,
)

val gate_skips_nullable_defaulted_fields_under_explicit_nulls by matrixSuite {
    "Nullable defaulted fields with the same tag are ambiguous when nulls are omitted" {
        shouldThrow<SerializationException> {
            DER.encodeToByteArray(GlNullableDefaultedCollision(a = 1))
        }.message shouldContain "Ambiguous ASN.1 layout"
    }

    "Explicit nulls do not hide ambiguity when defaults can still be omitted" {
        val der = DER { explicitNulls = true; encodeDefaults = false }
        shouldThrow<SerializationException> {
            der.encodeToByteArray(GlNullableDefaultedCollision(a = 1))
        }.message shouldContain "Ambiguous ASN.1 layout"
    }
}
