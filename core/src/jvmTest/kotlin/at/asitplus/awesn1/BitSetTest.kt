package at.asitplus.awesn1

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.boolean
import io.kotest.property.arbitrary.booleanArray
import io.kotest.property.arbitrary.int
import java.util.BitSet
import at.asitplus.awesn1.BitSet as KmpBitSet

val BitSetTest by matrixSuite {

    "Custom BitSet Implementation" - {
        "manual tests" {
            KmpBitSet.fromLogicalBitString("011011100101110111").toLogicalBitString() shouldBe "011011100101110111"

            val kmm = KmpBitSet(0)
            val jvm = BitSet(0)

            2.let {
                kmm[it.toLong()] = true
                jvm[it] = true
            }
            jvm.toString() shouldBe "{2}"
            kmm.toLogicalBitString() shouldBe "001"
            KmpBitSet.fromLogicalBitString(kmm.toLogicalBitString()) shouldBe kmm

            8.let {
                kmm[it.toLong()] = true
                jvm[it] = true
            }
            jvm.toString() shouldBe "{2, 8}"
            kmm.toLogicalBitString() shouldBe "001000001"
            KmpBitSet.fromLogicalBitString(kmm.toLogicalBitString()) shouldBe kmm


            2.let {
                kmm[it.toLong()] = false
                jvm[it] = false
            }

            jvm.toString() shouldBe "{8}"
            kmm.toLogicalBitString() shouldBe "000000001"
            KmpBitSet.fromLogicalBitString(kmm.toLogicalBitString()) shouldBe kmm

            10.let {
                kmm[it.toLong()] = false
                jvm[it] = false
            }

            jvm.toString() shouldBe "{8}"
            kmm.toLogicalBitString() shouldBe "000000001"
            KmpBitSet.fromLogicalBitString(kmm.toLogicalBitString()) shouldBe kmm


            8.let {
                kmm[it.toLong()] = false
                jvm[it] = false
            }

            jvm.toString() shouldBe "{}"
            kmm.toLogicalBitString() shouldBe ""
            KmpBitSet.fromLogicalBitString(kmm.toLogicalBitString()) shouldBe kmm


            val bits = BitSet()
            bits[2] = true; bits.memDump() shouldBe "00000100"
            bits[1] = true; bits.memDump() shouldBe "00000110"
            bits[0] = true; bits.memDump() shouldBe "00000111"
            bits[8] = true; bits.memDump() shouldBe "00000111 00000001"
        }

        "memDump manual tests" {
            byteArrayOf(4).memDumpView() shouldBe "00000100"
            byteArrayOf(7).memDumpView() shouldBe "00000111"
            byteArrayOf(17, 31).memDumpView() shouldBe "00010001 00011111"

            val kmm = KmpBitSet(0)
            val jvm = BitSet(0)

            2.let {
                kmm[it.toLong()] = true
                jvm[it] = true
            }
            jvm.memDump() shouldBe "00000100"
            kmm.memDumpView() shouldBe "00000100"

            8.let {
                kmm[it.toLong()] = true
                jvm[it] = true
            }
            jvm.memDump() shouldBe "00000100 00000001"
            kmm.memDumpView() shouldBe "00000100 00000001"


            2.let {
                kmm[it.toLong()] = false
                jvm[it] = false
            }

            jvm.memDump() shouldBe "00000000 00000001"
            kmm.memDumpView() shouldBe "00000000 00000001"

            10.let {
                kmm[it.toLong()] = false
                jvm[it] = false
            }

            jvm.memDump() shouldBe "00000000 00000001"
            kmm.memDumpView() shouldBe "00000000 00000001"


            8.let {
                kmm[it.toLong()] = false
                jvm[it] = false
            }

            jvm.memDump() shouldBe ""
            kmm.memDumpView() shouldBe ""
        }
        compact("automated") - {
            property(
                Arb.booleanArray(
                    Arb.int(1..128),
                    Arb.boolean()
                ),
                iterations = 32,
            ) - { input ->
                listOf(
                        input.size,
                        input.size / 2,
                        input.size / 3,
                        input.size / 4,
                        input.size / 8,
                        input.size / 10,
                        1,
                        0,
                        input.size * 2,
                        input.size * 4,
                    ).asData(name = "size") test { size: Int ->
                    val jvm = BitSet(size).also {
                        input.indices.shuffled().forEach { i -> it.set(i, input[i]) }
                    }
                    val kmm = withClue("size: $size") {
                        KmpBitSet(size.toLong()).also {
                            input.indices.shuffled().forEach { i -> it[i.toLong()] = input[i] }
                        }
                    }

                    input.forEachIndexed { i, b ->
                        withClue("jvm[$i]") { jvm[i] shouldBe b }
                        withClue("kmm[$i]") { kmm[i.toLong()] shouldBe b }
                    }

                    withClue("first bit set") { kmm.nextSetBit(0).toInt() shouldBe jvm.nextSetBit(0) }

                    val i = input.size - 1
                    withClue(
                        "first bit set in second half\n" +
                                "KMM: ${kmm.toLogicalBitString()}\n" +
                                "JVM: ${jvm.toString()}"
                    ) {
                        kmm.nextSetBit(i.toLong() / 2L).toInt() shouldBe jvm.nextSetBit(i / 2)
                    }
                    withClue(
                        "first bit set in last three quarters\n" +
                                "KMM: ${kmm.toLogicalBitString()}\n" +
                                "JVM: ${jvm.toString()}"
                    ) {
                        kmm.nextSetBit(i.toLong() / 4L).toInt() shouldBe jvm.nextSetBit(i / 4)
                    }
                    withClue(
                        "first bit set in last 4/5 of bit set\n" +
                                "KMM: ${kmm.toLogicalBitString()}\n" +
                                "JVM: ${jvm.toString()}"
                    ) {
                        kmm.nextSetBit(4L * i.toLong() / 5L).toInt() shouldBe jvm.nextSetBit(4 * i / 5)
                    }
                    kmm.toLsb0ByteArray() shouldBe jvm.toByteArray()


                    BitSet.valueOf(kmm.toLsb0ByteArray()).toByteArray() shouldBe jvm.toByteArray()
                    kmm.toLsb0ByteArray().toBitSet().toLsb0ByteArray() shouldBe jvm.toByteArray()
                    jvm.toByteArray().toBitSet().toLsb0ByteArray() shouldBe jvm.toByteArray()
                    kmm.toLsb0ByteArray().toBitSet().toLsb0ByteArray() shouldBe kmm.toLsb0ByteArray()

                    jvm.toByteArray().toBitSet().toLsb0ByteArray() shouldBe kmm.toLsb0ByteArray()
                    BitSet.valueOf(jvm.toByteArray()).toByteArray() shouldBe kmm.toLsb0ByteArray()
                    BitSet.valueOf(kmm.toLsb0ByteArray()).toByteArray() shouldBe kmm.toLsb0ByteArray()
                    BitSet.valueOf(jvm.toByteArray()).toByteArray() shouldBe jvm.toByteArray()
                }
            }
        }

        compact("toString() Tests") - {
            property(
                Arb.booleanArray(
                    Arb.int(1..128),
                    Arb.boolean()
                ),
                iterations = 32,
            ) - { input ->
                listOf(
                        input.size,
                        input.size / 2,
                        input.size / 3,
                        input.size / 4,
                        input.size / 8,
                        input.size / 10,
                        1,
                        0,
                        input.size * 2,
                        input.size * 4,
                    ).asData(name = "size") test { size ->
                    val jvm = BitSet(size).also {
                        input.indices.shuffled().forEach { i -> it.set(i, input[i]) }
                    }
                    val kmm = withClue("size: $size") {
                        KmpBitSet(size.toLong()).also {
                            input.indices.shuffled().forEach { i -> it[i.toLong()] = input[i] }
                        }
                    }

                    input.forEachIndexed { i, b ->
                        withClue("jvm[$i]") { jvm[i] shouldBe b }
                        withClue("kmm[$i]") { kmm[i.toLong()] shouldBe b }
                    }

                    val truncated = input.dropLastWhile { !it }
                    val monotonicOrderedStr = truncated.chunked(8)
                        .map { byte ->
                            (0..<8).map { runCatching { byte[it] }.getOrElse { false } }
                                .joinToString(separator = "") { if (it) "1" else "0" }
                        }.joinToString(separator = "") { it }.dropLastWhile { it == '0' }

                    kmm.toLogicalBitString() shouldBe monotonicOrderedStr
                }
            }
        }
    }
}

fun BitSet.memDump(): String = toByteArray().memDumpView()
