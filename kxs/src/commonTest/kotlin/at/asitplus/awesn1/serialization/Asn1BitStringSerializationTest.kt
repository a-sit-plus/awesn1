// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(ExperimentalStdlibApi::class)

package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.BitSet
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.SerializationException
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.json.Json

val Asn1BitStringSerializationTest by matrixSuite {
    val value = Asn1BitString(BitSet.fromLogicalBitString("001"))

    "A top-level BIT STRING retains its padding in DER" {
        DER.encodeToByteArray(value).toHexString() shouldBe "03020520"
        DER.decodeFromByteArray<Asn1BitString>("03020520".hexToByteArray()) shouldBe value
    }

    "A top-level BIT STRING retains its padding in JSON" {
        Json.encodeToString(Asn1BitString.serializer(), value) shouldBe "\"5:IA==\""
        Json.decodeFromString(Asn1BitString.serializer(), "\"5:IA==\"") shouldBe value
    }

    "DER decoding rejects nonzero BIT STRING padding" {
        shouldThrow<SerializationException> {
            DER.decodeFromByteArray<Asn1BitString>("03020301".hexToByteArray())
        }
    }

    "An empty BIT STRING round-trips through DER" {
        val empty = Asn1BitString(BitSet())
        DER.encodeToByteArray(empty).toHexString() shouldBe "030100"
        DER.decodeFromByteArray<Asn1BitString>("030100".hexToByteArray()) shouldBe empty
    }

    "An empty BIT STRING round-trips through JSON" {
        val empty = Asn1BitString(BitSet())
        Json.encodeToString(Asn1BitString.serializer(), empty) shouldBe "\"0:\""
        Json.decodeFromString(Asn1BitString.serializer(), "\"0:\"") shouldBe empty
    }
}
