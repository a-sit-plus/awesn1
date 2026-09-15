// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

/*
 * Mirror of :core's FallbackSerializerJsonTest. A string rendering of an ASN.1 value is not its DER encoding, so a
 * fallback serializer must be refused by the DER format on BOTH sides rather than emitting framing the format cannot
 * read back. The types' own serializers keep working.
 */

package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1IntegerDecimalStringSerializer
import at.asitplus.awesn1.Asn1IntegerHexStringSerializer
import at.asitplus.awesn1.Asn1Real
import at.asitplus.awesn1.Asn1RealStringSerializer
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.ObjectIdentifierStringSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlinx.serialization.SerializationException
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

@Serializable
data class DecStringIntegerHolder(
    @Serializable(with = Asn1IntegerDecimalStringSerializer::class) val v: Asn1Integer,
)

@Serializable
data class HexStringIntegerHolder(
    @Serializable(with = Asn1IntegerHexStringSerializer::class) val v: Asn1Integer,
)

@Serializable
data class StringOidHolder(
    @Serializable(with = ObjectIdentifierStringSerializer::class) val v: ObjectIdentifier,
)

@Serializable
data class StringRealHolder(
    @Serializable(with = Asn1RealStringSerializer::class) val v: Asn1Real,
)

@Serializable
data class NativeIntegerHolder(val v: Asn1Integer)

@OptIn(ExperimentalStdlibApi::class)
val FallbackSerializerDerRejection by matrixSuite {

    "a fallback serializer is refused when encoding to DER" {
        // Without the guard the encoder silently ignored the declared serializer and emitted the type's own
        // DER encoding — output its own decoder then rejected.
        shouldThrow<SerializationException> {
            DER.encodeToByteArray(DecStringIntegerHolder(Asn1Integer.fromDecimalString("7")))
        }.message shouldContain "non-DER fallback serializer"

        shouldThrow<SerializationException> {
            DER.encodeToByteArray(HexStringIntegerHolder(Asn1Integer.fromDecimalString("7")))
        }
        shouldThrow<SerializationException> {
            DER.encodeToByteArray(StringOidHolder(ObjectIdentifier("1.2.3")))
        }
        shouldThrow<SerializationException> {
            DER.encodeToByteArray(StringRealHolder(Asn1Real(1.5)))
        }
    }

    "a fallback serializer is refused when decoding from DER" {
        // 30 03 02 01 07 — a SEQUENCE holding INTEGER 7, i.e. the shape the native serializer produces.
        val nativeWire = "3003020107".hexToByteArray()

        shouldThrow<SerializationException> {
            DER.decodeFromByteArray<DecStringIntegerHolder>(nativeWire)
        }.message shouldContain "non-DER fallback serializer"

        shouldThrow<SerializationException> {
            DER.decodeFromByteArray<HexStringIntegerHolder>(nativeWire)
        }
    }

    "the type's own serializer is unaffected and still round-trips" {
        val value = NativeIntegerHolder(Asn1Integer.fromDecimalString("7"))
        val encoded = DER.encodeToByteArray(value)
        encoded.toHexString() shouldBe "3003020107"
        DER.decodeFromByteArray<NativeIntegerHolder>(encoded) shouldBe value

        // The other ASN.1-native types too, since their companions all declare a fallback for non-DER formats.
        DER.decodeFromByteArray<ObjectIdentifier>(
            DER.encodeToByteArray(ObjectIdentifier("1.2.840.113549"))
        ) shouldBe ObjectIdentifier("1.2.840.113549")
        DER.decodeFromByteArray<Asn1Real>(DER.encodeToByteArray(Asn1Real(1.5))) shouldBe Asn1Real(1.5)
    }
}
