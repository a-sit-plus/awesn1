package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.Asn1String
import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.matrixConfig
import de.infix.testBalloon.framework.core.invocation
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.assertions.throwables.shouldThrow
import kotlinx.serialization.SerializationException
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
