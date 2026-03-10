package at.asitplus.awesn1.serialization.api
import at.asitplus.awesn1.io.decodeFromSource
import at.asitplus.awesn1.io.encodeToSink
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import at.asitplus.awesn1.serialization.*


import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.Transient
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.serializer
import kotlin.jvm.JvmInline
import kotlin.reflect.typeOf


val TaggedTest by testSuite {
    withData(0, 2, 3, 4, 5, 6, 7, 8, 9) - { int ->
        "UntaggedInt" {
            Buffer().apply { DER.encodeToSink(UntaggedInt(int), this) }.readByteArray().toHexString() shouldBe "300302010$int".also {
                DER.decodeFromSource<UntaggedInt>(Buffer().apply { write(it.hexToByteArray()) }) shouldBe UntaggedInt(
                    int
                )
            }
        }
        "UntaggedAsn1Integer" {

            Buffer().apply { DER.encodeToSink(UntaggedAsn1Integer(int), this) }.readByteArray().toHexString() shouldBe "300302010$int".also {
                DER.decodeFromSource<UntaggedAsn1Integer>(Buffer().apply { write(it.hexToByteArray()) }) shouldBe UntaggedAsn1Integer(
                    int
                )
            }
        }
        "UntaggedElement" {
            Buffer().apply { DER.encodeToSink(UntaggedElement(int), this) }.readByteArray().toHexString() shouldBe "300302010$int".also {
                DER.decodeFromSource<UntaggedElement>(Buffer().apply { write(it.hexToByteArray()) }) shouldBe UntaggedElement(
                    int
                )
            }
        }
        "ImplicitlyTaggedElement" {
            shouldThrow<SerializationException> {
                Buffer().apply { DER.encodeToSink(ImplicitlyTaggedElement(int), this) }.readByteArray()
            }
            shouldThrow<SerializationException> {
                DER.decodeFromSource<ImplicitlyTaggedElement>(Buffer().apply { write("300389010$int".hexToByteArray()) })
            }
        }

        "ValueClassImplicitlyTaggedElement" {
            Buffer().apply { DER.encodeToSink(ValueClassImplicitlyTaggedElement(int), this) }.readByteArray().toHexString() shouldBe "300389010$int".also {
               val decoded=  DER.decodeFromSource<ValueClassImplicitlyTaggedElement>(Buffer().apply { write(it.hexToByteArray()) }) shouldBe ValueClassImplicitlyTaggedElement(
                    int
                )
                shouldThrow<SerializationException> {
                    DER.decodeFromSource<ValueClassImplicitlyTaggedElement>(Buffer().apply { write("300302010$int".hexToByteArray()) })
                }

                decoded.rawValue.tag.tagValue shouldBe 9uL
            }
        }

        "ValueClassImplicitlyTaggedComplexElement" {
            DER.encodeToTlv(ImplicitlyTaggedComplex(ComplexPayload(int))).toDerHexString() shouldBe "A90302010$int"
            Buffer().apply { DER.encodeToSink(ValueClassImplicitlyTaggedComplexElement(int), this) }.readByteArray().toHexString() shouldBe "3005a90302010$int"
                .also {
                    val decoded = DER.decodeFromSource<ValueClassImplicitlyTaggedComplexElement>(Buffer().apply { write(it.hexToByteArray()) })
                    decoded.value shouldBe ComplexPayload(int)
                    decoded.rawValue.tag.tagValue shouldBe 9uL
                }
        }
    }
}

@Serializable
data class UntaggedInt(val value: Int)

@Serializable
data class UntaggedAsn1Integer private constructor(val value: Asn1Integer) {
    constructor(value: Int) : this(Asn1Integer(value))
}

@Serializable
data class UntaggedElement private constructor(private val rawValue: Asn1Element) {
    //this is fine: default int tag, default int serializer, so everything just works, no manual parsing or custom serializer required
    constructor(value: Int) : this(DER.encodeToTlv(value))

    @Transient
    val value = DER.decodeFromTlv<Int>(rawValue)
}

@Serializable
data class ImplicitlyTaggedElement private constructor(@Asn1Tag(9u) private val rawValue: Asn1Element) {
    //The encoding path also works fine. default it serializer, no manual parsing or custom serializer required
    constructor(value: Int) : this(DER.encodeToTlv(value))

    @Transient
    //This is where deserialization fails, because Asn1Element does not have an int tag, but 0x89, so the default int serializer does not work due to a tag mismatch
    //The way around it would be to use a custom serializer or `decodeToInt` form the Asn1Element decoding functions

    //For this simple example this is not an issue, because there is such an int decoding function, but imagine we don't have int, but TbsCertificate, whose
    //raw ASN.1 representation is required (And yes, we want ASN.1 that round-trip deserializes and serializes to bytes, so we have structural guarantees; hence: raw bytes are not an option)
    val value = DER.decodeFromTlv<Int>(rawValue)
}

@Asn1Tag(9u)
@Serializable
@JvmInline
value class ImplicitlyTaggedInt(val value: Int)

@Serializable
data class ValueClassImplicitlyTaggedElement private constructor(val rawValue: Asn1Element) {
    constructor(value: Int) : this((DER.encodeToTlv(ImplicitlyTaggedInt(value))))

    @Transient
    val value: Int = DER.decodeFromTlv<ImplicitlyTaggedInt>(rawValue).value
}

@Serializable
data class ComplexPayload(val value: Int)

@Asn1Tag(9u)
@Serializable
@JvmInline
value class ImplicitlyTaggedComplex(val value: ComplexPayload)

@Serializable
data class ValueClassImplicitlyTaggedComplexElement private constructor(val rawValue: Asn1Element) {
    constructor(value: Int) : this(DER.encodeToTlv(ImplicitlyTaggedComplex(ComplexPayload(value))))

    @Transient
    val value: ComplexPayload = DER.decodeFromTlv<ImplicitlyTaggedComplex>(rawValue).value
}
