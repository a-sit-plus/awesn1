package at.asitplus.awesn1

import at.asitplus.awesn1.encoding.decodeFromDer
import at.asitplus.awesn1.encoding.encodeToDer
import at.asitplus.testballoon.matrix.matrixSuite
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.property.Arb
import io.kotest.property.RandomSource
import io.kotest.property.Sample
import io.kotest.property.arbitrary.*
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

@OptIn(ExperimentalUuidApi::class, ExperimentalStdlibApi::class)
val OidTest by matrixSuite {
    "OID test" - {

        "manual" {
            val oid = ObjectIdentifier("1.3.311.128.1.4.99991.9311.21.20")
            val oid1 = ObjectIdentifier("1.3.311.128.1.4.99991.9311.21.20")
            val oid2 = ObjectIdentifier("1.3.312.128.1.4.99991.9311.21.20")
            val oid3 = ObjectIdentifier("1.3.132.0.34")

            oid3.bytes shouldBe ObjectIdentifier.decodeFromDer(oid3.encodeToDer()).bytes
            oid.bytes shouldBe ObjectIdentifier.decodeFromDer(oid.encodeToDer()).bytes
            oid1.bytes shouldBe ObjectIdentifier.decodeFromDer(oid1.encodeToDer()).bytes
            oid2.bytes shouldBe ObjectIdentifier.decodeFromDer(oid2.encodeToDer()).bytes

            val encoded = oid.encodeToTlv()
            ObjectIdentifier.decodeFromTlv(encoded) shouldBe oid
            oid shouldBe oid1
            oid shouldNotBe oid2
            oid.hashCode() shouldBe oid1.hashCode()
            oid.hashCode() shouldNotBe oid2.hashCode()
        }

        compact("Full Root Arc") - {
            data(List(127) { it }, nameFn = { _, it -> "Byte $it" }) test { byte ->
                val oid = ObjectIdentifier.decodeFromAsn1ContentBytes(byteArrayOf(byte.toUByte().toByte()))
                val fromBC = ASN1ObjectIdentifier.fromContents(byteArrayOf(byte.toByte()))
                oid.encodeToDer() shouldBe fromBC.encoded
                ObjectIdentifier(oid.toString()).let {
                    it shouldBe oid
                    it.encodeToDer() shouldBe fromBC.encoded
                }
                ObjectIdentifier(*(oid.toString().split(".").map { it.toUInt() }.toUIntArray())).let {
                    it shouldBe oid
                    it.encodeToDer() shouldBe fromBC.encoded
                }
                ObjectIdentifier(oid.toString()).let {
                    it shouldBe oid
                    it.encodeToDer() shouldBe fromBC.encoded
                }
            }

            val stringRepesentations = mutableListOf<String>()
            repeat(39) { stringRepesentations += "0.$it" }
            repeat(39) { stringRepesentations += "1.$it" }
            repeat(255) { stringRepesentations += "2.$it" }
            data("string", stringRepesentations, nameFn = { _, it -> "String $it" }) test { string ->
                val oid = ObjectIdentifier(string)
                val fromBC = ASN1ObjectIdentifier(string)
                oid.encodeToDer() shouldBe fromBC.encoded
                ObjectIdentifier(oid.toString()).let {
                    it shouldBe oid
                    it.encodeToDer() shouldBe fromBC.encoded
                }
                ObjectIdentifier(*(oid.toString().split(".").map { it.toUInt() }.toUIntArray())).let {
                    it shouldBe oid
                    it.encodeToDer() shouldBe fromBC.encoded
                }
                ObjectIdentifier(oid.toString()).let {
                    it shouldBe oid
                    it.encodeToDer() shouldBe fromBC.encoded
                }
            }
        }
        compact("Failing Root Arc") - {
            data("byte", List(128) { it + 128 }, nameFn = { _, it -> "Byte $it" }) test { byte ->
                shouldThrow<Asn1Exception> {
                    ObjectIdentifier.decodeFromAsn1ContentBytes(byteArrayOf(byte.toUByte().toByte()))
                }
            }
            val stringRepesentations = mutableListOf<String>()

            repeat(255 - 40) { stringRepesentations += "0.${it + 40}" }
            repeat(255 - 40) { stringRepesentations += "1.${it + 40}" }
            repeat(255 - 3) { stringRepesentations += "${3 + it}.${it % 40}" }

            data("string", stringRepesentations, nameFn = { _, it -> "String $it" }) test { string ->
                shouldThrow<Asn1Exception> { ObjectIdentifier(string) }
            }

        }

        compact("Failing negative Bigints") - {
            property("negative", Arb.negativeInt(), iterations = 50) - { negativeInt ->
                property("second", Arb.positiveInt(39), iterations = 15) - { second ->
                    property(
                        "rest",
                        Arb.intArray(Arb.int(0..128), Arb.positiveInt(Int.MAX_VALUE)),
                        iterations = 100
                    ) test { rest ->
                        listOf(0, 1, 2).forEach { first ->
                            val withNegative =
                                intArrayOf(negativeInt, *rest).apply { shuffle() }.map { BigInteger(it) }
                                    .toTypedArray()
                            shouldThrow<Asn1Exception> {
                                ObjectIdentifier("$first.$second." + withNegative.joinToString("."))
                            }
                        }
                    }
                }
            }
        }
        compact("Automated UInt Capped") - {
            property("second", Arb.positiveInt(39), iterations = 15) - { second ->
                property(
                    "rest",
                    Arb.intArray(Arb.int(0..128), Arb.positiveInt(Int.MAX_VALUE)),
                    iterations = 500
                ) test { rest ->
                    listOf(0, 1, 2).forEach { first ->
                        val oid = ObjectIdentifier(
                            first.toUInt(),
                            second.toUInt(),
                            *(rest.map { it.toUInt() }.toUIntArray())
                        )

                        val stringRepresentation =
                            "$first.$second" + if (rest.isEmpty()) "" else ("." + rest.joinToString("."))

                        oid.toString() shouldBe stringRepresentation


                        val second1 = if (second > 1) second - 1 else second + 1

                        val oid1 = ObjectIdentifier(
                            first.toUInt(),
                            second1.toUInt(),
                            *(rest.map { it.toUInt() }.toUIntArray())
                        )
                        val parsed = ObjectIdentifier.decodeFromTlv(oid.encodeToTlv())
                        val fromBC = ASN1ObjectIdentifier(stringRepresentation)

                        val bcEncoded = fromBC.encoded
                        val ownEncoded = oid.encodeToDer()

                        @OptIn(ExperimentalStdlibApi::class)
                        withClue(
                            "Expected: ${bcEncoded.toHexString(HexFormat.UpperCase)}\nActual: ${
                                ownEncoded.toHexString(
                                    HexFormat.UpperCase
                                )
                            }"
                        ) {
                            bcEncoded shouldBe ownEncoded
                        }
                        parsed shouldBe oid
                        parsed.hashCode() shouldBe oid.hashCode()
                        parsed shouldNotBe oid1
                        parsed.hashCode() shouldNotBe oid1.hashCode()
                    }
                }
            }
        }

        compact("Automated BigInt") - {
            property("second", Arb.positiveInt(39), iterations = 15) - { second ->
                property("third", Arb.bigInt(1, 358), iterations = 500) test { generated ->
                    listOf(1, 2).forEach { first ->
                        val third = BigInteger.fromByteArray(generated.toByteArray(), Sign.POSITIVE)
                        val oid = ObjectIdentifier("$first.$second.$third")

                        val stringRepresentation =
                            "$first.$second.$third"

                        oid.toString() shouldBe stringRepresentation

                        val second1 = if (second > 1) second - 1 else second + 1

                        val oid1 = ObjectIdentifier("$first.$second1")
                        val parsed = ObjectIdentifier.decodeFromTlv(oid.encodeToTlv())
                        val fromBC = ASN1ObjectIdentifier(stringRepresentation)

                        val bcEncoded = fromBC.encoded
                        val ownEncoded = oid.encodeToDer()

                        @OptIn(ExperimentalStdlibApi::class)
                        withClue(
                            "Expected: ${bcEncoded.toHexString(HexFormat.UpperCase)}\nActual: ${
                                ownEncoded.toHexString(
                                    HexFormat.UpperCase
                                )
                            }"
                        ) {
                            bcEncoded shouldBe ownEncoded
                        }
                        parsed shouldBe oid
                        parsed.hashCode() shouldBe oid.hashCode()
                        parsed shouldNotBe oid1
                        parsed.hashCode() shouldNotBe oid1.hashCode()
                    }
                }
            }
        }

        "UUID" - {
            "550e8400-e29b-41d4-a716-446655440000" {
                val uuid = Uuid.parse("550e8400-e29b-41d4-a716-446655440000")
                val bigint = uuid.toBigInteger()
                bigint.toString() shouldBe "113059749145936325402354257176981405696"
                Uuid.fromBigintOrNull(bigint) shouldBe uuid
            }

            compact("random") - {
                property(object : Arb<Uuid>() {
                    override fun edgecase(rs: RandomSource): Sample<Uuid> = sample(rs)
                    override fun sample(rs: RandomSource): Sample<Uuid> =
                        Sample(uuidFromRandomBytes(rs.random.nextBytes(Uuid.SIZE_BYTES)))
                }, nameFn = { _, it -> it.toString() }) test { uuid ->
                    val bigint = uuid.toBigInteger()
                    bigint.toString() shouldBe BigInteger.parseString(uuid.toHexString(), 16).toString()
                    Uuid.fromBigintOrNull(bigint) shouldBe uuid

                    val oidString = "2.25.$bigint"
                    val oid = ObjectIdentifier(oidString)
                    oid.encodeToDer() shouldBe ASN1ObjectIdentifier(oidString).encoded
                    oid.nodes.size shouldBe 3
                    oid.nodes.first() shouldBe "2"
                    oid.nodes[1] shouldBe "25"
                    oid.nodes.last() shouldBe bigint.toString()

                    oid.toString() shouldBe oidString
                }
            }
        }
    }
}


//copied from Stdlib for reproducibility

private fun uuidFromRandomBytes(randomBytes: ByteArray): Uuid {
    randomBytes[6] = (randomBytes[6].toInt() and 0x0f).toByte() /* clear version        */
    randomBytes[6] = (randomBytes[6].toInt() or 0x40).toByte()  /* set to version 4     */
    randomBytes[8] = (randomBytes[8].toInt() and 0x3f).toByte() /* clear variant        */
    randomBytes[8] = (randomBytes[8].toInt() or 0x80).toByte()  /* set to IETF variant  */
    return Uuid.fromByteArray(randomBytes)
}
