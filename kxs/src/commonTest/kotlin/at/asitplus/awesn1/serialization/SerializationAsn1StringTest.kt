package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.Asn1String
import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.matrixConfig
import de.infix.testBalloon.framework.core.invocation
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.assertions.throwables.shouldThrow
import kotlinx.serialization.SerializationException
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestAsn1String by matrixSuite(
    matrixConfig { execution= ExecutionMode.Sequential }
) {
    "String" {
        val str = Asn1String.UTF8("foo")
        val serialized = DER.encodeToByteArray(str)

        DER.decodeFromByteArray<Asn1String>(serialized) shouldBe str
        DER.decodeFromByteArray<Asn1String.UTF8>(serialized) shouldBe str
    }

    "generic decoding preserves malformed strings while concrete decoding is strict" {
        val malformed = "1e0100".hexToByteArray()
        val generic = DER.decodeFromByteArray<Asn1String>(malformed)

        generic.isValid shouldBe false
        DER.encodeToByteArray<Asn1String>(generic).contentEquals(malformed) shouldBe true
        shouldThrow<SerializationException> { DER.decodeFromByteArray<Asn1String.BMP>(malformed) }
        shouldThrow<SerializationException> { DER.decodeFromByteArray<String>(malformed) }
    }

    "a concrete subtype only accepts its own tag; the generic base tolerates any" {
        val printable = "13024142".hexToByteArray() // PrintableString "AB"

        // A property typed as a concrete subtype declares that subtype's tag, and DER means it.
        shouldThrow<SerializationException> { DER.decodeFromByteArray<Asn1String.UTF8>(printable) }

        // Declaring the base type is the documented way to tolerate a producer that picked another
        // string type than the spec demands — the value keeps the tag it arrived with.
        val generic = DER.decodeFromByteArray<Asn1String>(printable)
        generic shouldBe Asn1String.Printable("AB")
        DER.encodeToByteArray<Asn1String>(generic).contentEquals(printable) shouldBe true
    }

    "disjoint concrete string subtypes do not collide in the ambiguity gate" {
        // UTF8String (0x0C) and PrintableString (0x13) cannot be confused, so an optional field of
        // one followed by the other is a decidable layout and must be expressible.
        val value = Asn1StringDisjointLayout(Asn1String.UTF8("x"), Asn1String.Printable("y"))
        val encoded = DER.encodeToByteArray(value)
        encoded.toHexString() shouldBe "30060c0178130179"
        DER.decodeFromByteArray<Asn1StringDisjointLayout>(encoded) shouldBe value

        // The omitted form still round-trips, and the trailing field keeps its own tag.
        val omitted = Asn1StringDisjointLayout(null, Asn1String.Printable("y"))
        DER.decodeFromByteArray<Asn1StringDisjointLayout>(DER.encodeToByteArray(omitted)) shouldBe omitted
    }

    "a nullable concrete subtype does not swallow a foreign string tag" {
        // 30 06 13 01 79 02 01 07 — PrintableString where UTF8String is declared. It must not be
        // reinterpreted as a UTF8String, and it must not be silently treated as an absent value.
        shouldThrow<SerializationException> {
            DER.decodeFromByteArray<Asn1StringNullableThenInt>("3006130179020107".hexToByteArray())
        }
        DER.decodeFromByteArray<Asn1StringNullableThenInt>("30060c0179020107".hexToByteArray()) shouldBe
                Asn1StringNullableThenInt(Asn1String.UTF8("y"), 7)
        DER.decodeFromByteArray<Asn1StringNullableThenInt>("3003020107".hexToByteArray()) shouldBe
                Asn1StringNullableThenInt(null, 7)
    }

    "Kotlin String decodes every supported ASN.1 string type" {
        listOf(
            "0c024142" to "AB",                 // UTF8String
            "1e0400410042" to "AB",             // BMPString
            "12023132" to "12",                 // NumericString
            "14024142" to "AB",                 // TeletexString
            "1a024142" to "AB",                 // VisibleString
            "1c080000004100000042" to "AB",     // UniversalString
            "13024142" to "AB",                 // PrintableString
            "16024142" to "AB",                 // IA5String
        ).forEach { (encoded, expected) ->
            DER.decodeFromByteArray<String>(encoded.hexToByteArray()) shouldBe expected
        }
    }
}

@Serializable
data class Asn1StringDisjointLayout(
    val a: Asn1String.UTF8? = null,
    val b: Asn1String.Printable,
)

@Serializable
data class Asn1StringNullableThenInt(
    val s: Asn1String.UTF8? = null,
    val n: Int,
)
