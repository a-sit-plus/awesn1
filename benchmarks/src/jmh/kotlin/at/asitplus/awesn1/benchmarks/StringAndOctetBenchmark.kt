// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.benchmarks

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1EncapsulatingOctetString
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.encoding.parse
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DEROctetString
import org.openjdk.jmh.annotations.Benchmark
import org.openjdk.jmh.annotations.Param
import org.openjdk.jmh.annotations.Scope
import org.openjdk.jmh.annotations.Setup
import org.openjdk.jmh.annotations.State
import java.math.BigInteger

@State(Scope.Benchmark)
open class OctetStringDecapsulationBenchmark {

    @Param("1", "16", "256")
    var depth: Int = 0

    private lateinit var der: ByteArray

    @Setup
    fun setup() {
        der = DERNull.INSTANCE.encoded
        repeat(depth) { der = DEROctetString(der).encoded }
        check(awesn1Decapsulate() is Asn1EncapsulatingOctetString)
        check(bouncyCastleDecapsulate() == DERNull.INSTANCE)
    }

    @Benchmark
    fun awesn1Decapsulate(): Asn1Element = Asn1Element.parse(der)

    @Benchmark
    fun bouncyCastleDecapsulate(): ASN1Primitive {
        var current = ASN1Primitive.fromByteArray(der)
        while (current is ASN1OctetString) current = ASN1Primitive.fromByteArray(current.octets)
        return current
    }
}

@State(Scope.Benchmark)
open class DecimalIntegerStringBenchmark {

    @Param("64", "2048", "16384")
    var bitLength: Int = 0

    private lateinit var decimal: String
    private lateinit var awesn1Integer: Asn1Integer
    private lateinit var bouncyCastleInteger: ASN1Integer

    @Setup
    fun setup() {
        val value = BigInteger.ONE.shiftLeft(bitLength - 1).add(BigInteger.valueOf(0x123456789L)).negate()
        decimal = value.toString()
        awesn1Integer = Asn1Integer.fromDecimalString(decimal)
        bouncyCastleInteger = ASN1Integer(value)
        check(awesn1Integer.toDecimalString() == decimal)
        check(bouncyCastleInteger.value.toString() == decimal)
    }

    @Benchmark
    fun awesn1FromDecimalString(): Asn1Integer = Asn1Integer.fromDecimalString(decimal)

    @Benchmark
    fun bouncyCastleFromDecimalString(): ASN1Integer = ASN1Integer(BigInteger(decimal))

    @Benchmark
    fun awesn1ToDecimalString(): String = awesn1Integer.toDecimalString()

    @Benchmark
    fun bouncyCastleToDecimalString(): String = bouncyCastleInteger.value.toString()
}

@State(Scope.Benchmark)
open class HexIntegerStringBenchmark {

    @Param("64", "2048", "16384", "131072", "1048576")
    var bitLength: Int = 0

    private lateinit var awesn1Hex: String
    private lateinit var bouncyCastleHex: String
    private lateinit var awesn1Integer: Asn1Integer
    private lateinit var bouncyCastleInteger: ASN1Integer

    @Setup
    fun setup() {
        val value = BigInteger.ONE.shiftLeft(bitLength - 1).add(BigInteger.valueOf(0x123456789L)).negate()
        awesn1Integer = Asn1Integer.fromTwosComplement(value.toByteArray())
        bouncyCastleInteger = ASN1Integer(value)
        awesn1Hex = awesn1Integer.toHexString()
        bouncyCastleHex = value.toString(16)
        check(Asn1Integer.fromHexString(awesn1Hex) == awesn1Integer)
        check(BigInteger(bouncyCastleHex, 16) == value)
    }

    @Benchmark
    fun awesn1FromHexString(): Asn1Integer = Asn1Integer.fromHexString(awesn1Hex)

    @Benchmark
    fun bouncyCastleFromHexString(): ASN1Integer = ASN1Integer(BigInteger(bouncyCastleHex, 16))

    @Benchmark
    fun awesn1ToHexString(): String = awesn1Integer.toHexString()

    @Benchmark
    fun bouncyCastleToHexString(): String = bouncyCastleInteger.value.toString(16)
}

@State(Scope.Benchmark)
open class ObjectIdentifierStringBenchmark {

    @Param("common", "uuid", "large")
    lateinit var fixture: String

    private lateinit var dotted: String
    private lateinit var content: ByteArray

    @Setup
    fun setup() {
        dotted = when (fixture) {
            "common" -> "1.2.840.113549.1.1.11"
            "uuid" -> "2.25.340282366920938463463374607431768211455"
            "large" -> "2.999." + List(64) { "123456789012345678901234567890" }.joinToString(".")
            else -> error("unknown fixture $fixture")
        }

        content = ObjectIdentifier(dotted).bytes
        check(ObjectIdentifier.decodeFromAsn1ContentBytes(content).toString() == dotted)
        check(ASN1ObjectIdentifier.fromContents(content).id == dotted)
    }

    @Benchmark
    fun awesn1FromString(): ObjectIdentifier = ObjectIdentifier(dotted)

    @Benchmark
    fun bouncyCastleFromString(): ASN1ObjectIdentifier = ASN1ObjectIdentifier(dotted)

    @Benchmark
    fun awesn1ToString(): String = ObjectIdentifier.decodeFromAsn1ContentBytes(content).toString()

    @Benchmark
    fun bouncyCastleToString(): String = ASN1ObjectIdentifier.fromContents(content).id
}
