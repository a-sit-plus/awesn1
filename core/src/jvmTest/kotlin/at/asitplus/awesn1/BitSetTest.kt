package at.asitplus.awesn1

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.boolean
import io.kotest.property.arbitrary.booleanArray
import io.kotest.property.arbitrary.int
import java.util.BitSet as JavaBitSet
import at.asitplus.awesn1.BitSet as KmpBitSet

val BitSetTest by matrixSuite {

    "Negative indices throw for accessors and setters" {
        shouldThrow<IndexOutOfBoundsException> { KmpBitSet()[-1] }
        shouldThrow<IndexOutOfBoundsException> { KmpBitSet()[-1] = true }
        shouldThrow<IndexOutOfBoundsException> { KmpBitSet()[-1..5] = true }
    }
    "Positive large indices throw only for setters" {
        KmpBitSet()[Long.MAX_VALUE] shouldBe false
        shouldThrow<Asn1Exception> { KmpBitSet()[Long.MAX_VALUE] = false }
    }

    "NextSetBit test" {
        val set = KmpBitSet(byteArrayOf(0b00101000, 0, 1))
        set.nextSetBitAfter(3) shouldBe 5
        set.nextSetBitAfter(5) shouldBe 16
    }

    "Custom BitSet Implementation" - {

        "manual tests" {
            KmpBitSet.fromString("011011100101110111").toBitStringView() shouldBe "011011100101110111"

            val kmm = KmpBitSet(0)
            val jvm = JavaBitSet(0)

            2.let {
                kmm[it.toLong()] = true
                jvm[it] = true
            }
            jvm.toString() shouldBe "{2}"
            kmm.toBitStringView() shouldBe "001"
            KmpBitSet.fromString(kmm.toBitStringView()) shouldBe kmm

            8.let {
                kmm[it.toLong()] = true
                jvm[it] = true
            }
            jvm.toString() shouldBe "{2, 8}"
            kmm.toBitStringView() shouldBe "001000001"
            KmpBitSet.fromString(kmm.toBitStringView()) shouldBe kmm


            2.let {
                kmm[it.toLong()] = false
                jvm[it] = false
            }

            jvm.toString() shouldBe "{8}"
            kmm.toBitStringView() shouldBe "000000001"
            KmpBitSet.fromString(kmm.toBitStringView()) shouldBe kmm

            10.let {
                kmm[it.toLong()] = false
                jvm[it] = false
            }

            jvm.toString() shouldBe "{8}"
            kmm.toBitStringView() shouldBe "000000001"
            KmpBitSet.fromString(kmm.toBitStringView()) shouldBe kmm


            8.let {
                kmm[it.toLong()] = false
                jvm[it] = false
            }

            jvm.toString() shouldBe "{}"
            kmm.toBitStringView() shouldBe ""
            KmpBitSet.fromString(kmm.toBitStringView()) shouldBe kmm


            val bits = KmpBitSet()
            bits[2] = true; bits.memDumpView() shouldBe "00000100"
            bits[1] = true; bits.memDumpView() shouldBe "00000110"
            bits[0] = true; bits.memDumpView() shouldBe "00000111"
            bits[8] = true; bits.memDumpView() shouldBe "00000111 00000001"
        }

        "memDump manual tests" {
            KmpBitSet(byteArrayOf(4)).memDumpView() shouldBe "00000100"
            KmpBitSet(byteArrayOf(7)).memDumpView() shouldBe "00000111"
            KmpBitSet(byteArrayOf(17, 31)).memDumpView() shouldBe "00010001 00011111"

            val kmm = KmpBitSet(0)
            val jvm = JavaBitSet(0)

            2.let {
                kmm[it.toLong()] = true
                jvm[it] = true
            }
            jvm.memDumpView() shouldBe "00000100"
            kmm.memDumpView() shouldBe "00000100"

            8.let {
                kmm[it.toLong()] = true
                jvm[it] = true
            }
            jvm.memDumpView() shouldBe "00000100 00000001"
            kmm.memDumpView() shouldBe "00000100 00000001"


            2.let {
                kmm[it.toLong()] = false
                jvm[it] = false
            }

            jvm.memDumpView() shouldBe "00000000 00000001"
            kmm.memDumpView() shouldBe "00000000 00000001"

            10.let {
                kmm[it.toLong()] = false
                jvm[it] = false
            }

            jvm.memDumpView() shouldBe "00000000 00000001"
            kmm.memDumpView() shouldBe "00000000 00000001"


            8.let {
                kmm[it.toLong()] = false
                jvm[it] = false
            }

            jvm.memDumpView() shouldBe ""
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
                    val jvm = JavaBitSet(size).also {
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
                                "KMM: ${kmm.toBitStringView()}\n" +
                                "JVM: ${jvm.toString()}"
                    ) {
                        kmm.nextSetBit(i.toLong() / 2L).toInt() shouldBe jvm.nextSetBit(i / 2)
                    }
                    withClue(
                        "first bit set in last three quarters\n" +
                                "KMM: ${kmm.toBitStringView()}\n" +
                                "JVM: ${jvm.toString()}"
                    ) {
                        kmm.nextSetBit(i.toLong() / 4L).toInt() shouldBe jvm.nextSetBit(i / 4)
                    }
                    withClue(
                        "first bit set in last 4/5 of bit set\n" +
                                "KMM: ${kmm.toBitStringView()}\n" +
                                "JVM: ${jvm.toString()}"
                    ) {
                        kmm.nextSetBit(4L * i.toLong() / 5L).toInt() shouldBe jvm.nextSetBit(4 * i / 5)
                    }
                    kmm.toByteArray() shouldBe jvm.toByteArray()
                    kmm.toJavaBitSet().toByteArray() shouldBe jvm.toByteArray()
                    jvm.toKmpBitSet().toByteArray() shouldBe kmm.toByteArray()
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
                    val jvm = JavaBitSet(size).also {
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

                    kmm.toBitStringView() shouldBe monotonicOrderedStr
                }
            }
        }
    }
}
private fun JavaBitSet.memDumpView(): String = toByteArray().joinToString(separator = " ") { it.toUByte().toString(2).padStart(8, '0') }
