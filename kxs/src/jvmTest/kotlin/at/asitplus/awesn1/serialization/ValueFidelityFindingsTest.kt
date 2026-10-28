// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(ExperimentalSerializationApi::class, ExperimentalStdlibApi::class)

package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.Asn1CustomStructure
import at.asitplus.awesn1.Asn1Element
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlin.jvm.JvmInline
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.SetSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.json.Json
import kotlinx.serialization.serializer

// Suite names preserve the original finding identifiers.
val lenientset_equals_multiplicity_collapse by matrixSuite {
    val wire = Asn1CustomStructure(
        listOf(DER.encodeToTlv(2), DER.encodeToTlv(1), DER.encodeToTlv(2)),
        Asn1Element.Tag.SET.tagValue,
    )
    val decoded = DER.decodeFromTlv<LenientSet<Int>>(wire)
    val clean = LenientSet(linkedSetOf(1, 2))

    "Decoded duplicates retain their size and DER encoding" {
        decoded.size shouldBe 3
        clean.size shouldBe 2
        DER.encodeToTlv(LenientSet.Serializer(Int.serializer()), decoded).derEncoded shouldNotBe
                DER.encodeToTlv(LenientSet.Serializer(Int.serializer()), clean).derEncoded
    }

    "A duplicate-bearing set remains distinct in equality and hash collections" {
        (decoded == clean) shouldBe false
        hashSetOf(decoded, clean).size shouldBe 2
    }
}

val lenientset_equals_reencode_divergence by matrixSuite {
    val serializer = LenientSet.Serializer(Int.serializer())
    val duplicated = DER.decodeFromByteArray(serializer, "3109020102020101020102".hexToByteArray())
    val clean = LenientSet(linkedSetOf(1, 2))

    "Validation and DER encoding distinguish duplicate-bearing sets" {
        shouldThrow<at.asitplus.awesn1.Asn1Exception> { duplicated.toValidatedSet() }
        clean.toValidatedSet() shouldBe setOf(1, 2)
        DER.encodeToTlv(serializer, duplicated).derEncoded.toHexString() shouldNotBe
                DER.encodeToTlv(serializer, clean).derEncoded.toHexString()
    }

    "Equality and hash collections also distinguish duplicate-bearing sets" {
        (duplicated == clean) shouldBe false
        hashSetOf<LenientSet<Int>>(duplicated, clean).size shouldBe 2
    }
}

val lenientset_crossformat_illegal_state_bypass by matrixSuite {
    "JSON duplicates and ordering cannot produce a noncanonical DER SET" {
        val serializer = LenientSet.Serializer(Int.serializer())
        val fromJson = Json.decodeFromString(serializer, "[2, 1, 2]")
        DER.encodeToTlv(serializer, fromJson).derEncoded.toHexString() shouldBe "3106020101020102"
    }
}

val lenientset_programmatic_illegal_emission_v2 by matrixSuite {
    val serializer = LenientSet.Serializer(Int.serializer())
    val programmatic = LenientSet(linkedSetOf(2, 1))
    val canonical = DER.encodeToTlv(serializer, programmatic).derEncoded

    "Programmatic sets encode canonically" {
        canonical.toHexString() shouldBe "3106020101020102"
    }

    "A JSON round-trip preserves canonical DER encoding" {
        val jsonRoundTripped = Json.decodeFromString(serializer, Json.encodeToString(serializer, programmatic))
        DER.encodeToTlv(serializer, jsonRoundTripped).derEncoded.toHexString() shouldBe canonical.toHexString()
    }

    "JSON duplicates cannot produce a duplicate-bearing DER SET" {
        val fromJsonDuplicates = Json.decodeFromString(serializer, "[1,1,2]")
        DER.encodeToTlv(serializer, fromJsonDuplicates).derEncoded.toHexString() shouldBe "3106020101020102"
    }
}

val map_duplicate_key_collapse by matrixSuite {
    "A Kotlin Set rejects duplicate wire elements" {
        shouldThrow<SerializationException> {
            DER.decodeFromByteArray(SetSerializer(Int.serializer()), "3106020101020101".hexToByteArray())
        }
    }

    "A Kotlin Map rejects duplicate wire keys" {
        shouldThrow<SerializationException> {
            DER.decodeFromByteArray(
                MapSerializer(String.serializer(), Int.serializer()),
                "300c0c016b0201010c016b020102".hexToByteArray(),
            )
        }
    }
}

val nullable_collection_element_silent_drop by matrixSuite {
    val listSerializer = ListSerializer(serializer<Int?>())

    "Explicit nulls preserve null list elements" {
        val explicit = DER { explicitNulls = true }
        explicit.decodeFromByteArray(listSerializer, explicit.encodeToByteArray(listSerializer, listOf(1, null, 3))) shouldBe
                listOf(1, null, 3)
    }

    "Omitted null list elements are rejected" {
        shouldThrow<SerializationException> {
            DER.encodeToByteArray(listSerializer, listOf(1, null, 3))
        }
    }

    "Omitted null map values are rejected" {
        val mapSerializer = MapSerializer(Int.serializer(), serializer<String?>())
        shouldThrow<SerializationException> {
            DER.encodeToByteArray(mapSerializer, mapOf(1 to null))
        }
    }
}

@Serializable
private data class GlWithUInt(val w: UInt)

@Serializable
@JvmInline
private value class GlUIntWrap(val v: UInt)

@Serializable
private data class GlWithUIntWrap(val w: GlUIntWrap)

val decodevalue_valueclass_unsigned_signed_fallback by matrixSuite {
    val minusOne = "30030201ff".hexToByteArray()

    "An unsigned property rejects a negative INTEGER" {
        shouldThrow<SerializationException> { DER.decodeFromByteArray<GlWithUInt>(minusOne) }
    }

    "An unsigned value class also rejects a negative INTEGER" {
        shouldThrow<SerializationException> { DER.decodeFromByteArray<GlWithUIntWrap>(minusOne) }
    }

    "An unsigned value class round-trips a value above the signed range" {
        val big = GlWithUIntWrap(GlUIntWrap(4_000_000_000u))
        DER.roundTrip<GlWithUIntWrap>(big) shouldBe big
    }
}

@Serializable
private data class GlStringHolder(val s: String)

val decodestring_lenient_lossy_string_normalization by matrixSuite {
    val wireE9 = "30031401e9".hexToByteArray()
    val wireEA = "30031401ea".hexToByteArray()

    "TeletexString byte E9 decodes using the Latin-1 compatibility profile" {
        DER.decodeFromByteArray<GlStringHolder>(wireE9).s shouldBe "é"
    }

    "TeletexString byte EA decodes using the Latin-1 compatibility profile" {
        DER.decodeFromByteArray<GlStringHolder>(wireEA).s shouldBe "ê"
    }
}

val decodestring_nonutf8_stringtype_misdecode by matrixSuite {
    "An OCTET STRING cannot decode as a String property" {
        shouldThrow<SerializationException> {
            DER.decodeFromByteArray<GlStringHolder>("300404024142".hexToByteArray())
        }
    }

    "A BMPString decodes as UTF-16BE text" {
        DER.decodeFromByteArray<GlStringHolder>(
            "300c1e0a00610064006d0069006e".hexToByteArray()
        ).s shouldBe "admin"
    }

    "A BMPString with an incomplete code unit is rejected" {
        shouldThrow<SerializationException> {
            DER.decodeFromByteArray<GlStringHolder>("30031e0100".hexToByteArray())
        }
    }

    "A BMPString surrogate is rejected" {
        shouldThrow<SerializationException> {
            DER.decodeFromByteArray<GlStringHolder>("30041e02d800".hexToByteArray())
        }
    }

    "A UniversalString decodes BMP and supplementary code points" {
        DER.decodeFromByteArray<GlStringHolder>(
            "300e1c0c000000410001f60000000042".hexToByteArray()
        ).s shouldBe "A\uD83D\uDE00B"
    }

    "A UniversalString with an incomplete code point is rejected" {
        shouldThrow<SerializationException> {
            DER.decodeFromByteArray<GlStringHolder>("30051c03000041".hexToByteArray())
        }
    }

    "A UniversalString surrogate is rejected" {
        shouldThrow<SerializationException> {
            DER.decodeFromByteArray<GlStringHolder>("30061c040000d800".hexToByteArray())
        }
    }

    "A UniversalString code point above the Unicode range is rejected" {
        shouldThrow<SerializationException> {
            DER.decodeFromByteArray<GlStringHolder>("30061c0400110000".hexToByteArray())
        }
    }
}
