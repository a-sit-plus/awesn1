// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1CustomStructure
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.SerializationException
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

val LenientSetTest by matrixSuite {
    listOf(
        Triple("3100", emptyList(), true),
        Triple("3106020101020102", listOf(1, 2), true),
        Triple("3106020102020101", listOf(2, 1), false),
        Triple("3109020101020101020102", listOf(1, 1, 2), false),
        Triple("3109020102020101020102", listOf(2, 1, 2), false),
    ).asData(
        name = "materialized source retains SET order and duplicates",
        nameFn = { it.first },
    ) - { (hex, expected, canonical) ->
        "a root SET can be traversed after its tree is inspected" {
            val decoded = DER.decodeFromByteArray<LenientSet<Int>>(hex.hexToByteArray())
            decoded.toList() shouldBe expected
            (decoded == LenientSet(expected.toSet())) shouldBe canonical
            DER.encodeToByteArray(decoded).toHexString() shouldBe hex
        }

        "a nested SET leaves the following sibling intact" {
            val content = hex + "020109"
            val bytes = "30${(content.length / 2).toString(16).padStart(2, '0')}$content".hexToByteArray()
            val (decoded, sibling) = DER.decodeFromByteArray<Pair<LenientSet<Int>, Int>>(bytes)
            decoded.toList() shouldBe expected
            (decoded == LenientSet(expected.toSet())) shouldBe canonical
            sibling shouldBe 9
            DER.encodeToByteArray(decoded to sibling) shouldBe bytes
        }
    }

    "equality and hash ignore element order" {
        val ordered = LenientSet(linkedSetOf(1, 2))
        val reversed = LenientSet(linkedSetOf(2, 1))

        (ordered == reversed) shouldBe true
        ordered.hashCode() shouldBe reversed.hashCode()
    }

    "programmatic sets encode as canonically sorted SETs" {
        DER.encodeToTlv(LenientSet(linkedSetOf(2, 1)))
            .asSet().children.map { DER.decodeFromTlv<Int>(it) } shouldBe listOf(1, 2)
    }

    "canonical decoded sets equal their programmatic equivalent" {
        val programmatic = LenientSet(linkedSetOf(2, 1))
        val decoded = DER.decodeFromTlv<LenientSet<Int>>(DER.encodeToTlv(programmatic))

        (decoded == programmatic) shouldBe true
        decoded.hashCode() shouldBe programmatic.hashCode()
    }

    "decoded sets retain wire order and duplicates" {
        val malformed = Asn1CustomStructure(
            listOf(DER.encodeToTlv(2), DER.encodeToTlv(1), DER.encodeToTlv(2)),
            Asn1Element.Tag.SET.tagValue,
        )

        val decoded = DER.decodeFromTlv<LenientSet<Int>>(malformed)

        decoded.toList() shouldBe listOf(2, 1, 2)
        DER.encodeToTlv(decoded).derEncoded shouldBe malformed.derEncoded
    }

    "regular Kotlin sets reject duplicates and re-encode canonically" {
        val duplicate = Asn1CustomStructure(
            listOf(DER.encodeToTlv(2), DER.encodeToTlv(1), DER.encodeToTlv(2)),
            Asn1Element.Tag.SET.tagValue,
        )
        shouldThrow<SerializationException> { DER.decodeFromTlv<Set<Int>>(duplicate) }

        val nonCanonical = Asn1CustomStructure(
            listOf(DER.encodeToTlv(2), DER.encodeToTlv(1)),
            Asn1Element.Tag.SET.tagValue,
        )
        val decoded = DER.decodeFromTlv<Set<Int>>(nonCanonical)

        decoded shouldBe setOf(1, 2)
        DER.encodeToTlv(decoded).asSet().children.map { DER.decodeFromTlv<Int>(it) } shouldBe listOf(1, 2)
    }

    "toValidatedSet rejects decoded duplicates" {
        val malformed = Asn1CustomStructure(
            listOf(DER.encodeToTlv(1), DER.encodeToTlv(1)),
            Asn1Element.Tag.SET.tagValue,
        )

        shouldThrow<Asn1Exception> {
            DER.decodeFromTlv<LenientSet<Int>>(malformed).toValidatedSet()
        }
    }
}
