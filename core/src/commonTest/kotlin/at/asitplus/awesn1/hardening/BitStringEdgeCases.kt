@file:OptIn(InternalAwesn1Api::class)
package at.asitplus.awesn1.at.asitplus.awesn1.hardening

import at.asitplus.awesn1.*
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlin.random.Random

expect val bitSetTestsCompacted: Boolean


val bitStringEdgeCases by testSuite {
    "empty (03 01 00)" {
        Asn1BitString.decodeFromTlv(Asn1Element.parseFromDerHexString("03 01 00") as Asn1Primitive) shouldBe Asn1BitString(
            byteArrayOf()
        )
    }

    withData(nameFn = { "$it padding bits" }, List(8) { it.toByte() }, compact = bitSetTestsCompacted) - { numPaddingBits ->

        withData(nameFn = { "raw length: $it" }, listOf(1, 2, 3), compact = bitSetTestsCompacted) - { len ->
            val bitStringStart = "03 0${len + 1} ${numPaddingBits.hexPadded()} "

            withData(nameFn = {
                it + "xx"
            }, List(40) { _ ->
                var name = bitStringStart
                repeat(len - 1) { name += Random.nextInt(0, 255).toByte().hexPadded() + " " }
                name
            }, compact = bitSetTestsCompacted) - { hexBytes ->

                val legal = legalFinalBytes(numPaddingBits.toInt())
                val illegal = List(255) { it.toByte() }.filterNot { it in legal }

                if (legal.isNotEmpty()) "zero-ed out (legal)" - {
                    withData(nameFn = { "xx = ${it.hexPadded()}" }, legal, compact = bitSetTestsCompacted) { i ->
                        val derEncoded = "$hexBytes${i.hexPadded()}"
                        Asn1BitString.decodeFromTlv(Asn1Element.parseFromDerHexString(derEncoded) as Asn1Primitive) shouldBe Asn1BitString.fromRawParts(
                            numPaddingBits, derEncoded.replace(" ", "").substring(6).hexToByteArray(HexFormat.UpperCase)
                        )
                    }
                }

                if (illegal.isNotEmpty()) "not zeroed-out illegal" - {
                    withData(
                        nameFn = { "xx = ${it.hexPadded()}" },
                        illegal,
                        compact = bitSetTestsCompacted
                    ) { i ->
                        shouldThrow<Asn1Exception> {
                            Asn1BitString.decodeFromTlv(Asn1Element.parseFromDerHexString("$hexBytes${i.hexPadded()}") as Asn1Primitive)
                        }.message shouldBe "Last $numPaddingBits padding bits must be zeroed out. Last byte is: ${
                            i.toUByte().toString(2).padStart(8, '0')
                        }"
                    }
                }
            }
        }
    }

    "Illegal number of padding bits" - {
        withData(
            nameFn = { "numPaddingBits = $it" },
            List(255) { it.toByte() }.filterNot { it < 8.toByte() },
            compact = bitSetTestsCompacted
        ) { numPaddingBits ->

            shouldThrow<Asn1Exception> {
                Asn1BitString.decodeFromTlv(Asn1Element.parseFromDerHexString("03 02 ${numPaddingBits.hexPadded()} 00") as Asn1Primitive)
            }.message shouldBe "Number of padding bits must be in range 0..7. Found: $numPaddingBits"
        }
    }

    "Only padding and no data" - {

        val legal = "03 01 00"
        legal {
            Asn1BitString.decodeFromTlv(Asn1Element.parseFromDerHexString(legal) as Asn1Primitive) shouldBe Asn1BitString(
                byteArrayOf()
            )
        }

        withData(List(7) { "03 01 ${(it + 1).toByte().hexPadded()}" }) { illegal ->
            shouldThrow<Asn1Exception> {
                Asn1BitString.decodeFromTlv(Asn1Element.parseFromDerHexString(illegal) as Asn1Primitive)
            }.message shouldBe "Raw bytes must not be empty if padding bits are set"
        }
    }

}

val manualBitStringPadding  by testSuite {
    "Three Padding bits (03 02 03 xx)" - {
        val legal = List(32) { i ->
            (i * 8).toByte()
        }
        "zero (legal)" - {
            withData(nameFn = { "xx = ${it.hexPadded()}" }, legal, compact = bitSetTestsCompacted) { i ->
                Asn1BitString.decodeFromTlv(Asn1Element.parseFromDerHexString("03 02 03 ${i.hexPadded()}") as Asn1Primitive) shouldBe Asn1BitString.fromRawParts(
                    0x03.toByte(), byteArrayOf(i)
                )
            }
        }

        "illegal" - {
            withData(
                nameFn = { "xx = ${it.hexPadded()}" },
                List(255) { it.toByte() }.filterNot { it in legal },
                compact = bitSetTestsCompacted
            ) { i ->
                shouldThrow<Asn1Exception> {
                    Asn1BitString.decodeFromTlv(Asn1Element.parseFromDerHexString("03 02 03 ${i.hexPadded()}") as Asn1Primitive)
                }.message shouldBe "Last 3 padding bits must be zeroed out. Last byte is: ${
                    i.toUByte().toString(2).padStart(8, '0')
                }"
            }

        }

    }
}

private fun Byte.hexPadded(): String = toUByte().toHexString(HexFormat.UpperCase).padStart(2, '0')

fun legalFinalBytes(paddingBits: Int): List<Byte> {
    require(paddingBits in 0..7)

    val step = 1 shl paddingBits
    val count = 256 / step

    return List(count) { i ->
        (i * step).toByte()
    }
}