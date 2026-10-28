// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(ExperimentalStdlibApi::class, at.asitplus.awesn1.InternalAwesn1Api::class)

package at.asitplus.awesn1.hardening

import at.asitplus.awesn1.Asn1Decodable
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1OctetString
import at.asitplus.awesn1.Asn1PemDecodable
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.decodeFromDerWithPemHeaders
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.encoding.parseAll
import at.asitplus.awesn1.wrapInUnsafeSource
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

val parse_limit_violation_throws_iae_not_asn1exception by matrixSuite {
    "Parsing a single element beyond the byte-array cap throws Asn1Exception" {
        shouldThrow<Asn1Exception> { Asn1Element.parse("020101".hexToByteArray(), limit = 2) }
    }

    "Parsing all elements beyond the byte-array cap throws Asn1Exception" {
        shouldThrow<Asn1Exception> { Asn1Element.parseAll("020101".hexToByteArray(), limit = 2) }
    }
}

val pem_decodefromderwithpemheaders_leaks_raw_cce by matrixSuite {
    val decoder = object : Asn1PemDecodable<Asn1Primitive, Asn1Integer>,
        Asn1Decodable<Asn1Primitive, Asn1Integer> by Asn1Integer.Companion {
        override val canonicalPemLabel = "ASN1 INTEGER"
    }

    "The direct PEM bridge decodes an INTEGER" {
        decoder.decodeFromDerWithPemHeaders(emptyList(), "020107".hexToByteArray()) shouldBe Asn1Integer(7)
    }

    "The direct PEM bridge wraps a wrong structural type as IllegalArgumentException" {
        shouldThrow<IllegalArgumentException> {
            decoder.decodeFromDerWithPemHeaders(emptyList(), "3003020101".hexToByteArray())
        }
    }
}

val octeststring_invoke_negative_length_truncation by matrixSuite {
    for (length in listOf(-1L, Long.MIN_VALUE + 1, -4294967296L)) {
        "Negative OCTET STRING length $length is rejected before narrowing or consuming input" {
            val source = byteArrayOf(1).wrapInUnsafeSource()
            shouldThrow<IllegalArgumentException> { Asn1OctetString(source, length) }
            source.readByte() shouldBe 1.toByte()
        }
    }
}
