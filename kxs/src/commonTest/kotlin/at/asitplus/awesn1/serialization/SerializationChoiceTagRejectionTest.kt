package at.asitplus.awesn1.serialization

import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.matrixConfig
import de.infix.testBalloon.framework.core.invocation
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlin.jvm.JvmInline

@OptIn(ExperimentalStdlibApi::class)
val SerializationChoiceTagRejectionTest by matrixSuite(
    matrixConfig { execution= ExecutionMode.Sequential }
) {
    "Rejects class tag on sealed class CHOICE when serialized directly" {
        shouldRejectChoiceTag("class") {
            DER.encodeToByteArray<TaggedChoiceClass>(TaggedChoiceClass.Text("x"))
        }
    }

    "Rejects class tag on sealed interface CHOICE when serialized directly" {
        shouldRejectChoiceTag("class") {
            DER.encodeToByteArray<TaggedChoiceInterface>(TaggedChoiceInterfaceText("x"))
        }
    }

    "Rejects class tag on sealed class CHOICE when serialized as property" {
        shouldRejectChoiceTag("class") {
            DER.encodeToByteArray(TaggedChoiceClassBox(TaggedChoiceClass.Text("x")))
        }
    }

    "Rejects class tag on sealed interface CHOICE when serialized as property" {
        shouldRejectChoiceTag("class") {
            DER.encodeToByteArray(TaggedChoiceInterfaceBox(TaggedChoiceInterfaceText("x")))
        }
    }

    "Rejects property tag on untagged sealed class CHOICE" {
        shouldRejectChoiceTag("property tag 42") {
            DER.encodeToByteArray(PropertyTaggedChoiceClassBox(UntaggedChoiceClass.Text("x")))
        }
    }

    "Rejects property tag on untagged sealed interface CHOICE" {
        shouldRejectChoiceTag("property tag 43") {
            DER.encodeToByteArray(PropertyTaggedChoiceInterfaceBox(UntaggedChoiceInterfaceText("x")))
        }
    }

    "Rejects inline tag on inline wrapper around sealed class CHOICE" {
        shouldRejectChoiceTag("inline tag 44") {
            DER.encodeToByteArray(InlineTaggedChoiceClassWrapper(UntaggedChoiceClass.Text("x")))
        }
    }

    "Rejects inline tag on inline wrapper around sealed interface CHOICE" {
        shouldRejectChoiceTag("inline tag 45") {
            DER.encodeToByteArray(InlineTaggedChoiceInterfaceWrapper(UntaggedChoiceInterfaceText("x")))
        }
    }

    "Untagged sealed class CHOICE round-trips directly and as property" {
        val direct = UntaggedChoiceClass.Text("A")
        val directDer = DER.encodeToByteArray<UntaggedChoiceClass>(direct)
        directDer.toHexString() shouldBe "30030c0141"
        DER.decodeFromByteArray<UntaggedChoiceClass>(directDer) shouldBe direct

        val boxed = UntaggedChoiceClassBox(direct)
        val boxedDer = DER.encodeToByteArray(boxed)
        boxedDer.toHexString() shouldBe "300530030c0141"
        DER.decodeFromByteArray<UntaggedChoiceClassBox>(boxedDer) shouldBe boxed
    }

    "Untagged sealed interface CHOICE round-trips directly and as property" {
        val direct = UntaggedChoiceInterfaceInt(7)
        val directDer = DER.encodeToByteArray<UntaggedChoiceInterface>(direct)
        directDer.toHexString() shouldBe "020107"
        DER.decodeFromByteArray<UntaggedChoiceInterface>(directDer) shouldBe direct

        val boxed = UntaggedChoiceInterfaceBox(direct)
        val boxedDer = DER.encodeToByteArray(boxed)
        boxedDer.toHexString() shouldBe "3003020107"
        DER.decodeFromByteArray<UntaggedChoiceInterfaceBox>(boxedDer) shouldBe boxed
    }
}

private fun shouldRejectChoiceTag(expectedSource: String, block: () -> Unit) {
    val message = shouldThrow<SerializationException>(block).message
    message shouldContain "@Asn1Tag on ASN.1 CHOICE is not supported"
    message shouldContain expectedSource
}

@Serializable
@Asn1Tag(40u)
private sealed class TaggedChoiceClass {
    @Serializable
    data class Text(val value: String) : TaggedChoiceClass()
}

@Serializable
@Asn1Tag(41u)
private sealed interface TaggedChoiceInterface

@Serializable
private data class TaggedChoiceInterfaceText(val value: String) : TaggedChoiceInterface

@Serializable
private data class TaggedChoiceClassBox(val choice: TaggedChoiceClass)

@Serializable
private data class TaggedChoiceInterfaceBox(val choice: TaggedChoiceInterface)

@Serializable
private sealed class UntaggedChoiceClass {
    @Serializable
    data class Text(val value: String) : UntaggedChoiceClass()
}

@Serializable
private sealed interface UntaggedChoiceInterface

@Serializable
@JvmInline
private value class UntaggedChoiceInterfaceText(val value: String) : UntaggedChoiceInterface

@Serializable
@JvmInline
private value class UntaggedChoiceInterfaceInt(val value: Int) : UntaggedChoiceInterface

@Serializable
private data class UntaggedChoiceClassBox(val choice: UntaggedChoiceClass)

@Serializable
private data class UntaggedChoiceInterfaceBox(val choice: UntaggedChoiceInterface)

@Serializable
private data class PropertyTaggedChoiceClassBox(
    @Asn1Tag(42u)
    val choice: UntaggedChoiceClass,
)

@Serializable
private data class PropertyTaggedChoiceInterfaceBox(
    @Asn1Tag(43u)
    val choice: UntaggedChoiceInterface,
)

@Serializable
@Asn1Tag(44u)
@JvmInline
private value class InlineTaggedChoiceClassWrapper(val choice: UntaggedChoiceClass)

@Serializable
@Asn1Tag(45u)
@JvmInline
private value class InlineTaggedChoiceInterfaceWrapper(val choice: UntaggedChoiceInterface)
