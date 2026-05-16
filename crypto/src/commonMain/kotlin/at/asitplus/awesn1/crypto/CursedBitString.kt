@file:OptIn(at.asitplus.awesn1.InternalAwesn1Api::class)

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.*
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.awesn1.serialization.Asn1Serializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlin.jvm.JvmInline

/**
 * **Es gibt nichts Gutes, außer man tut es!**
 *
 * This value class foregoes strict ASN.1 BIT STRING validation, because everyone knows, even binding specifications
 * are often treated more like rough guidelines that only apply to small fry. If you are too big to fail, the world has
 * to deal with the mess you make.
 *
 * It is intentionally impossible for downstream to create an instance of this class.
 */
@JvmInline
//we need to roll this by hand, because a value class with a byte array comes straight from hell:
// equals will never work and cannot be overridden
@Serializable(with = CursedBitString.Companion::class)
value class CursedBitString private constructor(
    private val primitive: Asn1Primitive
) : Asn1BitStringish, Asn1Encodable<Asn1Primitive> {

    /**
     * Creates a [CursedBitString] from the provided [strict] [Asn1BitString].
     */
    internal constructor(strict: Asn1BitString) : this(strict.encodeToTlv())

    private val contentBytes: ByteArray get() = primitive.content

    init {
        require(numPaddingBits in 0..7) { "Number of padding bits must be in range 0..7" }
        if (contentBytes.isNotEmpty()) require(contentBytes.size > 1) { "Even cursed bit strings must be structurally valid" }
    }

    override val numPaddingBits: Byte get() = if (contentBytes.isEmpty()) 0 else contentBytes.first()
    override val rawBytes: ByteArray
        get() = if (contentBytes.isEmpty()) ByteArray(0) else contentBytes.copyOfRange(1, contentBytes.size)

    /**
     * Converts the current instance of [CursedBitString] to a strict [Asn1BitString].
     *
     * This function constructs an [Asn1BitString] using the padding bits and raw bytes of the
     * [CursedBitString].
     *
     * @return A strict [Asn1BitString] instance based on the content of this [CursedBitString].
     * @throws IllegalStateException If the constraints within [Asn1BitString.fromRawParts] are violated.
     */
    fun toBitString() = @OptIn(InternalAwesn1Api::class) Asn1BitString.fromRawParts(numPaddingBits, rawBytes)

    override fun encodeToTlv(): Asn1Primitive = primitive

    override fun toString(): String = "CursedBitString(contentBytes=${contentBytes.contentToString()})"

    companion object : Asn1Serializer<Asn1Primitive, CursedBitString>(
        leadingTags = setOf(Asn1Element.Tag.BIT_STRING),
        decodable = object : Asn1Decodable<Asn1Primitive, CursedBitString> {
            override fun doDecode(src: Asn1Primitive): CursedBitString =
                CursedBitString(Asn1Primitive(Asn1Element.Tag.BIT_STRING, src.content))
        },
    ) {
        override val descriptor: SerialDescriptor =
            PrimitiveSerialDescriptor(ASN1_DESCRIPTOR_BIT_STRING, PrimitiveKind.STRING)
    }
}

/**
 * Exception-free version of [toBitString]
 */
fun CursedBitString.toBitStringOrNull() = catchingUnwrapped { toBitString() }.getOrNull()
