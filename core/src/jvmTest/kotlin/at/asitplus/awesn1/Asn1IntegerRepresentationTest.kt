package at.asitplus.awesn1

import at.asitplus.awesn1.encoding.decodeAsn1VarBigInt
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.positiveInt
import java.math.BigInteger
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

@OptIn(ExperimentalUuidApi::class)
val Asn1IntegerRepresentationTest by matrixSuite {

    "Manual" - {
        listOf("1027", "256", "1", "3", "8", "127", "128", "255", "512", "1024").asData(name = "integer") test { integer ->
            val bigInt = BigInteger(integer)
            val ref = bigInt.toString()
            val own = VarUInt.fromDecimalString(ref)
            val ownBytes = own.bytes
            val javaBytes = bigInt.toByteArray()
            val bigitBytes = javaBytes.dropWhile { it == 0.toByte() && javaBytes.size > 1 }.map { it.toUByte() }


            own.toDecimalString() shouldBe ref
            ownBytes shouldBe bigitBytes

            val varInt = own.toAsn1VarInt()
            val refVarint = BigInteger(bigInt.toString()).toAsn1VarInt()
            varInt shouldBe refVarint
            refVarint.decodeAsn1VarBigInt().first.uint.words shouldBe own.words
        }
    }


    compact("Automated") - {
        property("bytes", Arb.byteArray(Arb.positiveInt(65), Arb.byte())) test { bytes ->
            val bigInt = BigInteger(1,bytes)
            val ref = bigInt.toString()
            val own = VarUInt.fromDecimalString(ref)
            val ownBytes = own.bytes
            val javaBytes = bigInt.toByteArray()
            val bigitBytes = javaBytes.dropWhile { it == 0.toByte() && javaBytes.size > 1 }.map { it.toUByte() }

            own.toDecimalString() shouldBe ref
            ownBytes shouldBe bigitBytes
            own.toAsn1VarInt() shouldBe BigInteger(bigInt.toString()).toAsn1VarInt()
        }
    }

    compact("UUIDs") - {
        data( List<Uuid>(100) { Uuid.random() }, nameFn = { it.toHexString() }) test { uuid ->
            val bigint = BigInteger(1,uuid.toByteArray())
            val own = Asn1Integer.fromUnsignedByteArray(uuid.toByteArray()).toJavaBigInteger()
            own shouldBe bigint
        }
    }

    "TwosComplement" - {
        "manual" - {
            listOf(
                    "-24519924295662886907187464938912882392492723242957571281",
                    "-1457686090107523769986476796769829633039407019130",
                    "-18440417236681064435",
                    "-1",
                ).asData(name = "integer") test { integer ->
                val neg = BigInteger(integer)
                val ownNeg = Asn1Integer.fromDecimalString(neg.toString())
                withClue(neg.toString()) {
                    ownNeg.toDecimalString() shouldBe neg.toString()
                    ownNeg.twosComplement() shouldBe neg.toByteArray()
                }
            }
        }

        compact("automated") - {
            property("bytes", Arb.byteArray(Arb.positiveInt(349), Arb.byte())) test { bytes ->
                val pos = BigInteger(1,bytes)
                val neg = BigInteger(-1,bytes)

                val ownPos = Asn1Integer.fromDecimalString(pos.toString())
                ownPos.toDecimalString() shouldBe pos.toString()
                ownPos.twosComplement() shouldBe pos.toByteArray()
                val ownNeg = Asn1Integer.fromDecimalString(neg.toString())
                withClue(neg.toString()) {
                    ownNeg.toDecimalString() shouldBe neg.toString()
                    ownNeg.twosComplement() shouldBe neg.toByteArray()
                }
                Asn1Integer.fromTwosComplement(ownPos.twosComplement()) shouldBe ownPos
                Asn1Integer.fromTwosComplement(ownNeg.twosComplement()) shouldBe ownNeg
            }
        }

        "large negative round-trip" {
            val bytes = ByteArray(4096) { index -> ((index * 37) and 0xFF).toByte() }.also { it[0] = 0x80.toByte() }
            val neg = BigInteger(bytes)
            val ownNeg = Asn1Integer.fromTwosComplement(bytes)

            ownNeg.toDecimalString() shouldBe neg.toString()
            ownNeg.twosComplement() shouldBe bytes
        }
    }
}
