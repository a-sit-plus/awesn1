package at.asitplus.awesn1

import at.asitplus.awesn1.encoding.*
import at.asitplus.awesn1.encoding.internal.*
import at.asitplus.testballoon.matrix.matrixSuite
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.base63.toJavaBigInteger
import com.ionspin.kotlin.bignum.integer.toBigInteger
import com.ionspin.kotlin.bignum.integer.util.fromTwosComplementByteArray
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.*
import org.bouncycastle.asn1.ASN1Integer
import kotlin.math.pow

@OptIn(InternalAwesn1Api::class)
val Asn1NumberEncodingTest by matrixSuite {


    "Asn1 Number encoding" - {
        data(
            "Manual",
            listOf(
                257L,
                2f.pow(24).toLong() - 1,
                65555,
                2f.pow(24).toLong(),
                15253481L,
                -1446230472L,
                0L,
                1L,
                -1L,
                -2L,
                -9994587L,
                340281555L,
            ),
        ) test { value ->
            val bytes = (value).toTwosComplementByteArray()

            val fromBC = ASN1Integer(value).encoded
            val long = Long.decodeFromAsn1ContentBytes(bytes)

            val encoded = Asn1Primitive(Asn1Element.Tag.INT, bytes).derEncoded
            encoded shouldBe fromBC
            long shouldBe value

            bytes.wrapInUnsafeSource().readTwosComplementLong(bytes.size) shouldBe value
        }
    }


    compact("longs") - {
        "failures" - {
            property("too small", Arb.bigInt(128), iterations = 5000) test { value ->
                val v = BigInteger.fromLong(Long.MIN_VALUE).minus(1)
                    .minus(BigInteger.fromTwosComplementByteArray(value.toByteArray()))
                shouldThrow<Asn1Exception> { Asn1.Int(v.toJavaBigInteger().toAsn1Integer()).decodeToLong() }
            }
            property("too large", Arb.bigInt(128), iterations = 5000) test { value ->
                val v = BigInteger.fromLong(Long.MAX_VALUE).plus(1)
                    .plus(BigInteger.fromTwosComplementByteArray(value.toByteArray()))
                shouldThrow<Asn1Exception> { Asn1.Int(v.toJavaBigInteger().toAsn1Integer()).decodeToLong() }
            }
        }
        property("successes", Arb.long(), iterations = 150000) test { value ->
            val seq = Asn1.Sequence { +Asn1.Int(value) }
            val decoded = (seq.iterator().next() as Asn1Primitive).decodeToLong()
            decoded shouldBe value

            Asn1.Int(value).derEncoded shouldBe ASN1Integer(value).encoded

            val toTwosComplementByteArray = value.toTwosComplementByteArray()
            toTwosComplementByteArray.wrapInUnsafeSource()
                .readTwosComplementLong(toTwosComplementByteArray.size) shouldBe value
            ByteArraySink().apply { writeTwosComplementLong(value) }
                .readByteArray() shouldBe toTwosComplementByteArray
        }
    }

    compact("ints") - {
        "failures" - {
            property(
                "too small",
                Arb.long(Long.MIN_VALUE..<Int.MIN_VALUE.toLong()),
                iterations = 5000
            ) test { value ->
                shouldThrow<Asn1Exception> { Asn1.Int(value).decodeToInt() }
            }
            property(
                "too large",
                Arb.long(Int.MAX_VALUE.toLong() + 1..<Long.MAX_VALUE),
                iterations = 5000
            ) test { value ->
                shouldThrow<Asn1Exception> { Asn1.Int(value).decodeToInt() }
            }
        }
        property("successes", Arb.int(), iterations = 75000) test { value ->
            val seq = Asn1.Sequence { +Asn1.Int(value) }
            val decoded = (seq.iterator().next() as Asn1Primitive).decodeToInt()
            decoded shouldBe value

            Asn1.Int(value).derEncoded shouldBe ASN1Integer(value.toLong()).encoded
            val twosComplementByteArray = value.toTwosComplementByteArray()
            twosComplementByteArray.wrapInUnsafeSource()
                .readTwosComplementInt(twosComplementByteArray.size) shouldBe value
            twosComplementByteArray.wrapInUnsafeSource()
                .readTwosComplementLong(twosComplementByteArray.size) shouldBe value
        }
    }

    compact("unsigned ints") - {
        "failures" - {
            property("negative", Arb.long(Long.MIN_VALUE..<0), iterations = 5000) test { value ->
                shouldThrow<Asn1Exception> { Asn1.Int(value).decodeToUInt() }
            }

            property(
                "too large",
                Arb.long(UInt.MAX_VALUE.toLong() + 1..Long.MAX_VALUE),
                iterations = 5000
            ) test { value ->
                shouldThrow<Asn1Exception> { Asn1.Int(value).decodeToUInt() }
            }
        }
        property("successes", Arb.uInt(), iterations = 75000) test { value ->
            val seq = Asn1.Sequence { +Asn1.Int(value) }
            val decoded = (seq.iterator().next() as Asn1Primitive).decodeToUInt()
            decoded shouldBe value

            Asn1.Int(value).derEncoded shouldBe ASN1Integer(value.toBigInteger().toJavaBigInteger()).encoded
            val twosComplementByteArray = value.toTwosComplementByteArray()
            twosComplementByteArray.wrapInUnsafeSource()
                .readTwosComplementUInt(twosComplementByteArray.size) shouldBe value
            twosComplementByteArray.wrapInUnsafeSource()
                .readTwosComplementULong(twosComplementByteArray.size) shouldBe value.toULong()
        }
    }

    compact("unsigned longs") - {
        data(
            "manual",
            listOf(
                2f.pow(24).toULong() - 1u,
                256uL,
                65555uL,
                2f.pow(24).toULong(),
                255uL,
                360uL,
                4113774321109173852uL,
            ),
        ) test { value ->
            val bytes = (value).toTwosComplementByteArray()
            bytes.wrapInUnsafeSource().readTwosComplementULong(bytes.size) shouldBe value
        }

        "failures" - {
            property("negative", Arb.long(Long.MIN_VALUE..<0), iterations = 5000) test { value ->
                shouldThrow<Asn1Exception> { Asn1.Int(value).decodeToULong() }
            }
            property("negative", Arb.bigInt(128), iterations = 5000) test { value ->
                val byteArray = value.toByteArray()
                val v = BigInteger.fromULong(ULong.MAX_VALUE).plus(1).plus(
                    BigInteger.fromTwosComplementByteArray(
                        byteArray
                    )
                )
                val asn1Primitive = Asn1.Int(v.toJavaBigInteger().toAsn1Integer())
                shouldThrow<Asn1Exception> { asn1Primitive.decodeToULong() }
            }
        }
        property("successes", Arb.uLong(), iterations = 75000) test { value ->
            val seq = Asn1.Sequence { +Asn1.Int(value) }
            val decoded = (seq.iterator().next() as Asn1Primitive).decodeToULong()
            decoded shouldBe value

            Asn1.Int(value).derEncoded shouldBe ASN1Integer(value.toBigInteger().toJavaBigInteger()).encoded
            val twosComplementByteArray = value.toTwosComplementByteArray()
            twosComplementByteArray.wrapInUnsafeSource()
                .readTwosComplementULong(twosComplementByteArray.size) shouldBe value
        }
    }


}
