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

val LenientSetTest by matrixSuite {
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
