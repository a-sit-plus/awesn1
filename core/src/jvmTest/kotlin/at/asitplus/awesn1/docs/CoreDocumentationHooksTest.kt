package at.asitplus.awesn1.docs

import at.asitplus.awesn1.*
import at.asitplus.awesn1.Asn1Element.Tag.Template.Companion.withClass
import at.asitplus.awesn1.Asn1Element.Tag.Template.Companion.without
import at.asitplus.awesn1.encoding.*
import at.asitplus.awesn1.serialization.*
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

// --8<-- [start:core-hook-custom-type]
private data class SemanticVersion(
    val major: Int,
    val minor: Int,
) : Asn1Encodable<Asn1Sequence> {
    override fun encodeToTlv(): Asn1Sequence = Asn1.Sequence {
        +Asn1.Int(major)
        +Asn1.Int(minor)
    }

    companion object : Asn1Decodable<Asn1Sequence, SemanticVersion> {
        override fun doDecode(src: Asn1Sequence): SemanticVersion = src.decodeRethrowing {
            SemanticVersion(
                major = next().asPrimitive().decodeToInt(),
                minor = next().asPrimitive().decodeToInt(),
            )
        }
    }
}
// --8<-- [end:core-hook-custom-type]

// --8<-- [start:core-hook-serialization-choice-rfc]
@Serializable
private sealed interface Rfc5280GeneralName

@Serializable
@JvmInline
@Asn1Tag(
    tagNumber = 2u,
    tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
    constructed = Asn1ConstructedBit.PRIMITIVE,
)
private value class Rfc5280DnsName(
    val value: String,
) : Rfc5280GeneralName

@Serializable
@JvmInline
@Asn1Tag(
    tagNumber = 6u,
    tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
    constructed = Asn1ConstructedBit.PRIMITIVE,
)
private value class Rfc5280UriName(
    val value: String,
) : Rfc5280GeneralName

private fun coreHookSerializationChoiceRfcDer(): Pair<ByteArray, ByteArray> {
    val dnsName: Rfc5280GeneralName = Rfc5280DnsName("example.com")
    val uriName: Rfc5280GeneralName = Rfc5280UriName("https://example.com")

    val dnsDer = DER.encodeToByteArray(dnsName)
    dnsDer.toHexString() shouldBe "820b6578616d706c652e636f6d" /* (1)! */
    DER.decodeFromByteArray<Rfc5280GeneralName>(dnsDer) shouldBe dnsName

    val uriDer = DER.encodeToByteArray(uriName)
    uriDer.toHexString() shouldBe "861368747470733a2f2f6578616d706c652e636f6d" /* (2)! */
    DER.decodeFromByteArray<Rfc5280GeneralName>(uriDer) shouldBe uriName

    return dnsDer to uriDer
}
// --8<-- [end:core-hook-serialization-choice-rfc]

// --8<-- [start:core-hook-serialization-signedbox-definitions]
@Serializable
private data class ExamplePayload(
    val algorithmIdentifier: ObjectIdentifier,
    val creationTimeEpochSeconds: Long,
    val validUntilEpochSeconds: Long,
    val integrityFlag: Boolean,
    val payloadData: ByteArray,
)

@Serializable
@JvmInline
@Asn1Tag(tagNumber = 1u)
private value class ImplicitlyTaggedPayload(
    val value: ExamplePayload,
)

@Serializable
private data class SignedBox private constructor(
    val rawPayload: Asn1Element,
    @Asn1Tag(tagNumber = 2u)
    val signature: ByteArray,
) {

    //public constructor ensures only valid data is passed
    constructor(payload: ExamplePayload, signature: ByteArray) : this(
        rawPayload = DER.encodeToTlv(ImplicitlyTaggedPayload(payload)),
        signature = signature
    )

    //hidden from serialization, but eager init ensure the data is semantically correct
    //if you want to be even more lenient, mage it a getter that throws
    @Transient
    val payload: ExamplePayload = DER.decodeFromTlv<ImplicitlyTaggedPayload>(rawPayload).value


}
// --8<-- [end:core-hook-serialization-signedbox-definitions]

private fun coreHookSerializationSignedBoxDer(): Pair<ByteArray, ByteArray> {
    // --8<-- [start:core-hook-serialization-signedbox-roundtrip]
    val payload = ExamplePayload(
        algorithmIdentifier = ObjectIdentifier("1.2.840.113549.1.1.11"),
        creationTimeEpochSeconds = 1_736_203_200,
        validUntilEpochSeconds = 1_767_739_200,
        integrityFlag = true,
        payloadData = "deadbeef".hexToByteArray(),
    )
    val canonicalBox = SignedBox(
        payload,
        signature = "0102030405".hexToByteArray(),
    )

    canonicalBox.rawPayload.tag shouldBe
            /* (1)!*/ Asn1Element.Tag(1uL, constructed = true, tagClass = TagClass.CONTEXT_SPECIFIC)

    fun assertEquivalentPayload(decoded: ExamplePayload, payload: ExamplePayload) {
        decoded.algorithmIdentifier shouldBe payload.algorithmIdentifier
        decoded.creationTimeEpochSeconds shouldBe payload.creationTimeEpochSeconds
        decoded.validUntilEpochSeconds shouldBe payload.validUntilEpochSeconds
        decoded.integrityFlag shouldBe payload.integrityFlag
        decoded.payloadData.contentEquals(payload.payloadData) shouldBe true
    }

    val canonicalDer = DER.encodeToByteArray(canonicalBox)
    canonicalDer.toHexString() shouldBe
            /* (2)! */ "3029a12006092a864886f70d01010b0204677c5bc00204695d8f400101ff0404deadbeef82050102030405"


    val decodedCanonical = DER.decodeFromByteArray<SignedBox>(canonicalDer)
    assertEquivalentPayload(decodedCanonical.payload, payload)
    decodedCanonical.rawPayload.derEncoded.toHexString().contains("0101ff") shouldBe true

    // Some in-the-wild encoders emit BOOLEAN TRUE as 0x01 instead of DER-canonical 0xFF.
    val nonCanonical =
        DER.decodeFromByteArray<SignedBox>(canonicalDer.toHexString().replaceFirst("0101ff", "010101").hexToByteArray())

    val nonCanonicalDer = DER.encodeToByteArray(nonCanonical)

    //non-canonical boolean is kept: 0x00 = false, other single-byte values are considered true
    nonCanonicalDer.toHexString() shouldBe
            /* (3)! */ "3029a12006092a864886f70d01010b0204677c5bc00204695d8f400101010404deadbeef82050102030405"
    // --8<-- [end:core-hook-serialization-signedbox-roundtrip]

    return canonicalDer to nonCanonicalDer
}

private fun coreHookBuilderDer(): ByteArray {
// --8<-- [start:core-hook-builder]
    val frame = Asn1.Sequence {
        +Asn1.Int(7)
        +Asn1.Bool(true)
        +Asn1.UtcTime(kotlin.time.Instant.parse("2026-01-01T12:30:45Z"))
    }
    val derHex = frame.derEncoded.toHexString()
    derHex shouldBe /* (1)! */"30150201070101ff170d3236303130313132333034355a"
// --8<-- [end:core-hook-builder]
    return frame.derEncoded
}

private fun lowLevelDslTaggingDer(): ByteArray {
// --8<-- [start:lowlevel-hook-dsl-tagging]
    val tagged = Asn1.Sequence {
        +Asn1.ExplicitlyTagged(1u) {
            +Asn1.Bool(false)
        }
        +(Asn1.Utf8String("Foo") withImplicitTag (0xCAFEuL withClass TagClass.PRIVATE))
        +(Asn1.Sequence { +Asn1.Int(42) } withImplicitTag (0x5EuL without CONSTRUCTED))
    }
    tagged.derEncoded.toHexString() shouldBe /* (1)! */"3013a103010100df83957e03466f6f9f5e0302012a"
// --8<-- [end:lowlevel-hook-dsl-tagging]
    return tagged.derEncoded
}

private fun coreHookCustomRoundtripDer(): ByteArray {
// --8<-- [start:core-hook-custom-roundtrip]
    val version = SemanticVersion(major = 1, minor = 42)
    val der = version.encodeToDer()
    der.toHexString() shouldBe "300602010102012a" /* (1)! */
    SemanticVersion.decodeFromDer(der) shouldBe version
// --8<-- [end:core-hook-custom-roundtrip]
    return der
}

private fun lowLevelParseAndAssertDer(): ByteArray {
// --8<-- [start:lowlevel-hook-parse-and-assert]
    val der = "020101020102".hexToByteArray()
    val (first, remaining) = Asn1Element.parseFirst(der)
    first.assertTag(Asn1Element.Tag.INT)
    first.toDerHexString() shouldBe "020101"
    remaining.toHexString() shouldBe "020102"
    first.asPrimitive().decodeToInt() shouldBe 1
// --8<-- [end:lowlevel-hook-parse-and-assert]
    return first.derEncoded
}

private fun lowLevelContentBytesDer(): ByteArray {
// --8<-- [start:lowlevel-hook-content-bytes]
    val contentOnly = 300.encodeToAsn1ContentBytes()
    contentOnly.toHexString() shouldBe "012c"
    val der = Asn1.Int(300).derEncoded
    der.toHexString() shouldBe "0202012c"
    Int.decodeFromAsn1ContentBytes(contentOnly) shouldBe 300
// --8<-- [end:lowlevel-hook-content-bytes]
    return der
}

private fun coreHookPemGeneric() {
// --8<-- [start:core-hook-pem-generic]
    val source = """
        -----BEGIN CERTIFICATE-----
        AQID
        -----END CERTIFICATE-----
        -----BEGIN PUBLIC KEY-----
        BAUG
        -----END PUBLIC KEY-----
    """.trimIndent()

    val blocks: List<PemBlock> = decodeAllFromPem(source)
    blocks.map { it.label } shouldBe listOf("CERTIFICATE", "PUBLIC KEY")

    val encryptedLegacy = PemBlock(
        label = "RSA PRIVATE KEY",
        headers = listOf(
            PemHeader("Proc-Type", "4,ENCRYPTED"),
            PemHeader("DEK-Info", "AES-256-CBC,00112233445566778899AABBCCDDEEFF")
        ),
        payload = byteArrayOf(1, 2, 3)
    )

    val pemText = encodeAllToPem(listOf(encryptedLegacy))
    decodeFromPem(pemText).headers.map { it.name } shouldBe listOf("Proc-Type", "DEK-Info")
// --8<-- [end:core-hook-pem-generic]
}

private fun coreHookPemAsn1() {
// --8<-- [start:core-hook-pem-asn1]
    val source = object : Asn1PemEncodable<Asn1Primitive> {
        override val pemLabel: String = "ASN1 INTEGER"
        override fun encodeToTlv(): Asn1Primitive = Asn1Integer(42).encodeToTlv()
    }

    val decoder = object : Asn1PemDecodable<Asn1Primitive, Asn1Integer>,
        Asn1Decodable<Asn1Primitive, Asn1Integer> by Asn1Integer.Companion {}

    val pem = source.encodeToPem()
    decoder.decodeFromPem(pem) shouldBe Asn1Integer(42)
// --8<-- [end:core-hook-pem-asn1]
}

@OptIn(ExperimentalStdlibApi::class)
val CoreDocumentationHooks by testSuite(
    testConfig = DefaultConfiguration
) {
    "Core serialization hook models RFC 5280 GeneralName CHOICE" {
        val (dnsDer, uriDer) = coreHookSerializationChoiceRfcDer()
        emitAsn1JsSample("core-hook-serialization-choice-dns", dnsDer)
        emitAsn1JsSample("core-hook-serialization-choice-uri", uriDer)
    }

    "Core serialization hook models SignedBox with raw payload preservation" {
        val (canonicalDer, nonCanonicalDer) = coreHookSerializationSignedBoxDer()
        emitAsn1JsSample("core-hook-serialization-signedbox-canonical", canonicalDer)
        emitAsn1JsSample("core-hook-serialization-signedbox-noncanonical", nonCanonicalDer)
    }

    "Core builder hook composes ASN.1 frames" {
        emitAsn1JsSample("core-hook-builder", coreHookBuilderDer())
    }

    "Low-level DSL example includes explicit and implicit tagging" {
        emitAsn1JsSample("lowlevel-hook-dsl-tagging", lowLevelDslTaggingDer())
    }

    "Custom Asn1Encodable/Asn1Decodable hook round-trips" {
        emitAsn1JsSample("core-hook-custom-roundtrip", coreHookCustomRoundtripDer())
    }

    "Low-level parseFirst + assertTag workflow composes" {
        emitAsn1JsSample("lowlevel-hook-parse-and-assert", lowLevelParseAndAssertDer())
    }

    "Content-byte helper functions are inverses for Int" {
        emitAsn1JsSample("lowlevel-hook-content-bytes", lowLevelContentBytesDer())
    }

    "PEM generic hook parses mixed blocks and legacy headers" {
        coreHookPemGeneric()
    }

    "PEM ASN.1 bridge hook round-trips DER payloads inside PEM" {
        coreHookPemAsn1()
    }
}
