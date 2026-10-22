package at.asitplus.awesn1.hardening

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.encoding.decodeToTeletextString
import at.asitplus.awesn1.encoding.parse
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
private data class T61Vector(
    val der: String,
    val shouldParse: Boolean,
    val expectedUtf8: String?,
)

private fun t61ResourceText(path: String): String =
    object {}.javaClass.classLoader?.getResourceAsStream(path)
        ?.reader(Charsets.UTF_8)?.use { it.readText() }
        ?: error("Resource not found: $path")

private val t61Vectors = t61ResourceText("fixtures/boringssl/t61.json")
    .lineSequence()
    .map(String::trim)
    .filter { it.startsWith("{\"der\":") }
    .map { Json.decodeFromString<T61Vector>(it.removeSuffix(",")) }
    .toList()

val T61StringFindingsTest by matrixSuite {
    "corpus integrity" {
        t61Vectors.size shouldBe 267
        t61Vectors.count { it.shouldParse } shouldBe 260
        t61Vectors.count { !it.shouldParse } shouldBe 7
        t61Vectors.filterNot { it.shouldParse }.all { it.expectedUtf8 == null } shouldBe true
    }

    data(
        "BoringSSL T61 vectors",
        t61Vectors,
        nameFn = { "${if (it.shouldParse) "valid" else "invalid"}-${it.der.ifEmpty { "empty-input" }}" },
    ) - { vector ->
        if (!vector.shouldParse) {
            "unparsable" {
                shouldThrow<Asn1Exception> {
                    val primitive = Asn1Element.parse(vector.der.hexToByteArray()) as Asn1Primitive
                    primitive.decodeToTeletextString().value
                }
            }
        } else {
            val expected = requireNotNull(vector.expectedUtf8)
            val primitive = Asn1Element.parse(vector.der.hexToByteArray()) as Asn1Primitive
            "Correct Tag" {
                primitive.tag shouldBe Asn1Element.Tag.STRING_T61
            }

            "correct DER-encoding" {
                primitive.derEncoded.toHexString() shouldBe vector.der
            }
            val decoded = primitive.decodeToTeletextString()
            "correct decoding" {
                decoded.value shouldBe expected
            }
            "no overclaiming" {
                decoded.isValid shouldBe null
            }
            "byte-identical raw data" {
                decoded.rawValue shouldBe primitive.content
            }
            "Re-encodes correctly" {
                decoded.encodeToTlv().derEncoded.toHexString() shouldBe vector.der
            }
            "String constructor preserves decoded text" {
                Asn1String.Teletex(decoded.value).value shouldBe expected
            }
            "String constructor reproduces original DER" {
                Asn1String.Teletex(decoded.value).encodeToTlv().derEncoded.toHexString() shouldBe vector.der
            }
        }
    }
}
