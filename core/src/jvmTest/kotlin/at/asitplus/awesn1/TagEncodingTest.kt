@file:OptIn(ExperimentalStdlibApi::class)

package at.asitplus.awesn1

import at.asitplus.awesn1.encoding.*
import at.asitplus.awesn1.encoding.internal.ByteArraySink
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.positiveInt
import io.kotest.property.arbitrary.uInt
import io.kotest.property.arbitrary.uLong
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DERTaggedObject

@OptIn(InternalAwesn1Api::class)
val TagEncodingTest by matrixSuite {

    "fails" {
        val it = 2204309167L
        val bytes = (it).toTwosComplementByteArray()
        val fromBC = ASN1Integer(it).encoded
        val long = Long.decodeFromAsn1ContentBytes(bytes)
        val encoded = Asn1.Int(it).derEncoded
        encoded shouldBe fromBC
        long shouldBe it
    }

    compact("length encoding")- {
        property(Arb.positiveInt()) test { length ->
            ByteArraySink().apply { encodeLength(length.toLong()) }.readByteArray() shouldBe length.encodeLength()
        }
    }

    listOf(207692171uL, 128uL, 36uL, 16088548868045964978uL, 15871772363588580035uL).asData(name = "Manual") test { tagValue ->
        tagValue.toAsn1VarInt().decodeAsn1VarULong().first shouldBe tagValue
        val tag = Asn1Element.Tag(tagValue, constructed = tagValue % 2uL == 0uL)
        tag.tagValue shouldBe tagValue

    }
    compact("automated") - {
        property("Construction only", Arb.uLong(), iterations = 100000) test { tagValue ->
            tagValue.toAsn1VarInt().decodeAsn1VarULong().first shouldBe tagValue
            Asn1Element.Tag(
                tagValue,
                constructed = tagValue % 2uL == 0uL,
                tagClass = TagClass.CONTEXT_SPECIFIC
            ).tagValue shouldBe tagValue
        }
        property("Against BC", Arb.int(min = 1), iterations = 1000000) test { tagNumber ->
            val tag = Asn1Element.Tag(tagNumber.toULong(), constructed = false)
            tag.tagValue shouldBe tagNumber.toULong()

            val bc = DERTaggedObject(true, tagNumber, ASN1Integer(1337))
            val own = Asn1.ExplicitlyTagged(tagNumber.toULong()) {
                +Asn1.Int(1337)
            }
            withClue(
                "Expected: ${bc.encoded.toHexString(HexFormat.UpperCase)}, actual: ${
                    own.derEncoded.toHexString(
                        HexFormat.UpperCase
                    )
                }"
            ) { own.derEncoded shouldBe bc.encoded }
        }
    }

    listOf(207692171, 1337).asData(name = "Manual against BC") test { tagNumber ->
        val tag = Asn1Element.Tag(tagNumber.toULong(), constructed = false)
        tag.tagValue shouldBe tagNumber.toULong()

        val bc = DERTaggedObject(true, tagNumber, ASN1Integer(1337))
        val own = Asn1.ExplicitlyTagged(tagNumber.toULong()) {
            +Asn1.Int(1337)
        }
        withClue(
            "Expected: ${bc.encoded.toHexString(HexFormat.UpperCase)}, actual: ${
                own.derEncoded.toHexString(
                    HexFormat.UpperCase
                )
            }"
        ) { own.derEncoded shouldBe bc.encoded }
    }

    compact("automated ints") - {
        property("Ints", Arb.uInt(), iterations = 100000) test { int ->
            int.toAsn1VarInt().apply {
                decodeAsn1VarULong().first.toUInt() shouldBe int
                decodeAsn1VarULong().first shouldBe int.toULong()
                decodeAsn1VarUInt().first shouldBe int
            }
        }
    }
}
