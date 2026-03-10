package at.asitplus.awesn1

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json

val PemOpenSslFixtureTest by testSuite {

    val json = Json { ignoreUnknownKeys = false }

    fun assertPemBlocksEqual(expected: List<PemBlock>, actual: List<PemBlock>, context: String) {
        actual.size shouldBe expected.size
        expected.zip(actual).forEachIndexed { i, (left, right) ->
            right.label shouldBe left.label
            right.headers shouldBe left.headers
            (right.payload contentEquals left.payload) shouldBe true
        }
    }

    fun resourceText(path: String): String =
        object {}.javaClass.classLoader.getResourceAsStream(path)
            ?.reader(Charsets.UTF_8)
            ?.readText()
            ?: throw IllegalArgumentException("Resource not found: $path")

    "openssl fixture corpus round trips" {
        val root = json.decodeFromString<PemOpenSslFixtureSet>(resourceText("pem_openssl_fixtures.json"))
        root.fixtures.forEach { fixture ->
            val src = resourceText("fixtures/openssl/${fixture.file}")
            val decoded = decodeAllFromPem(src)

            decoded.map { it.label } shouldBe fixture.expectedLabels
            decoded.map { block -> block.headers.map { it.name } } shouldBe fixture.expectedHeaderNamesByBlock

            val roundTrippedAll = decodeAllFromPem(decoded.encodeAllToPem())
            assertPemBlocksEqual(decoded, roundTrippedAll, fixture.file)

            decoded.forEachIndexed { i, block ->
                val decodedAgain = decodeFromPem(block.encodeToPem())
                assertPemBlocksEqual(listOf(block), listOf(decodedAgain), "${fixture.file}[$i]")
            }
        }
    }

    "quirk fixtures cover lenient and failure cases" {
        val root = json.decodeFromString<PemQuirkFixtureSet>(resourceText("pem_quirks.json"))
        root.cases.forEach { fixture ->
            val src = fixture.pemLines.joinToString("\n")
            if (fixture.shouldFail) {
                shouldThrow<IllegalArgumentException> { decodeAllFromPem(src) }
                return@forEach
            }

            val decoded = decodeAllFromPem(src)
            decoded.map { it.label } shouldBe fixture.expectedLabels

            if (fixture.expectedHeaderNamesByBlock.isNotEmpty()) {
                decoded.map { block -> block.headers.map { it.name } } shouldBe fixture.expectedHeaderNamesByBlock
            }

            val roundTripped = decodeAllFromPem(decoded.encodeAllToPem())
            assertPemBlocksEqual(decoded, roundTripped, fixture.name)
        }
    }
}
