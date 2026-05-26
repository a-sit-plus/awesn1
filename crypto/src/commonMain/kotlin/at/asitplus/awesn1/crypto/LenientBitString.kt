@file:OptIn(at.asitplus.awesn1.InternalAwesn1Api::class)

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.ASN1_DESCRIPTOR_BIT_STRING
import at.asitplus.awesn1.Asn1Decodable
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Encodable
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.catchingUnwrapped
import at.asitplus.awesn1.serialization.Asn1Serializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlin.jvm.JvmName

/**
 * BIT STRING wrapper that preserves malformed (non-zeroed-out) padding bits.
 */
@Serializable(with = LenientBitString.Companion::class)
data class LenientBitString private constructor(
    private val primitive: Asn1Primitive,
) : Asn1Encodable<Asn1Primitive> {

    internal constructor(strict: Asn1BitString) : this(strict.encodeToTlv())

    private val raw: ByteArray get() = primitive.content

    init {
        require(numPaddingBits in 0..7) { "Number of padding bits must be in range 0..7" }
        if (raw.isNotEmpty()) require(raw.size > 1) { "Even lenient bit strings must be structurally valid" }
    }

    val numPaddingBits: Byte get() = if (raw.isEmpty()) 0 else raw.first()
    val bitCarryingBytes: ByteArray
        get() = if (raw.isEmpty()) ByteArray(0) else raw.copyOfRange(1, raw.size)

    /**
     * Parses and validates this lenient bit string into a strict [Asn1BitString].
     *
     * Getter may throw but we cannot annotate due to https://youtrack.jetbrains.com/issue/KT-63047/Throws-annotation-on-getter-leads-to-compile-time-error-for-iOS-target
     */
    val strict: Asn1BitString by lazy {
        Asn1BitString.fromRawParts(numPaddingBits, bitCarryingBytes)
    }

    override fun encodeToTlv(): Asn1Primitive = primitive

    companion object : Asn1Serializer<Asn1Primitive, LenientBitString>(
        leadingTags = setOf(Asn1Element.Tag.BIT_STRING),
        decodable = object : Asn1Decodable<Asn1Primitive, LenientBitString> {
            override fun doDecode(src: Asn1Primitive): LenientBitString =
                LenientBitString(Asn1Primitive(Asn1Element.Tag.BIT_STRING, src.content))
        },
    ) {
        override val descriptor: SerialDescriptor =
            PrimitiveSerialDescriptor(ASN1_DESCRIPTOR_BIT_STRING, PrimitiveKind.STRING)
    }
}

/**
 * Non-throwing variante of [LenientBitString.strict] that returns null if the bit string is malformed.
 */
val LenientBitString.strictOrNull: Asn1BitString?  get() = catchingUnwrapped { strict }.getOrNull()

internal operator fun LenientBitString.getValue(thisRef: Any?, property: Any?): Asn1BitString = strict

@JvmName("getNullableLenientBitStringValue")
internal operator fun LenientBitString?.getValue(thisRef: Any?, property: Any?): Asn1BitString? = this?.strict
