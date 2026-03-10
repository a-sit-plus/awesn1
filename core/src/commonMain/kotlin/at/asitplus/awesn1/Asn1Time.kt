// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(InternalAwesn1Api::class)

package at.asitplus.awesn1

import at.asitplus.awesn1.encoding.encodeToAsn1GeneralizedTimePrimitive
import at.asitplus.awesn1.encoding.encodeToAsn1UtcTimePrimitive
import at.asitplus.awesn1.encoding.decodeGeneralizedTimeFromAsn1ContentBytes
import at.asitplus.awesn1.encoding.decodeToInstant
import at.asitplus.awesn1.encoding.decodeUtcTimeFromAsn1ContentBytes
import at.asitplus.awesn1.serialization.Asn1Serializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlin.time.Instant

/**
 * ASN.1 TIME (required since GENERALIZED TIME and UTC TIME exist)
 *
 * @param instant the timestamp to encode
 * @param formatOverride to force either GENERALIZED TIME or UTC TIME
 */
@Serializable(with = Asn1Time.Companion::class)
class Asn1Time(instant: Instant, formatOverride: Format? = null) : Asn1Encodable<Asn1Primitive> {

    val instant = Instant.fromEpochSeconds(instant.epochSeconds)

    /**
     * Indicates whether this timestamp uses UTC TIME or GENERALIZED TIME
     */
    val format: Format =
        formatOverride ?: if (this.instant !in THRESHOLD_UTC_TIME..<THRESHOLD_GENERALIZED_TIME) {
            Format.GENERALIZED
        } else {
            Format.UTC
        }

    companion object : Asn1Serializer<Asn1Primitive, Asn1Time>(
        leadingTags = setOf(Asn1Element.Tag.TIME_UTC, Asn1Element.Tag.TIME_GENERALIZED),
        decodable = object : Asn1Decodable<Asn1Primitive, Asn1Time> {
            @Throws(Asn1Exception::class)
            override fun doDecode(src: Asn1Primitive) =
                Asn1Time(src.decodeToInstant(), if (src.tag == Asn1Element.Tag.TIME_UTC) Format.UTC else Format.GENERALIZED)
        },
        fallbackSerializer = Asn1TimeSerializer,
    ) {
        override val descriptor: SerialDescriptor =
            PrimitiveSerialDescriptor(ASN1_DESCRIPTOR_TIME, PrimitiveKind.STRING)

        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(src: Asn1Primitive, assertTag: Asn1Element.Tag?): Asn1Time {
            verifyTag(src, assertTag)
            val effectiveTag = assertTag ?: src.tag
            return when (effectiveTag) {
                Asn1Element.Tag.TIME_UTC ->
                    Asn1Time(Instant.decodeUtcTimeFromAsn1ContentBytes(src.content), Format.UTC)

                Asn1Element.Tag.TIME_GENERALIZED ->
                    Asn1Time(Instant.decodeGeneralizedTimeFromAsn1ContentBytes(src.content), Format.GENERALIZED)

                else -> {
                    catchingUnwrapped { Instant.decodeUtcTimeFromAsn1ContentBytes(src.content) }
                        .getOrNull()
                        ?.let { return Asn1Time(it, Format.UTC) }

                    catchingUnwrapped { Instant.decodeGeneralizedTimeFromAsn1ContentBytes(src.content) }
                        .getOrNull()
                        ?.let { return Asn1Time(it, Format.GENERALIZED) }

                    throw Asn1StructuralException("Unsupported ASN.1 time tag $effectiveTag")
                }
            }
        }

        private val THRESHOLD_UTC_TIME = Instant.parse("1950-01-01T00:00:00Z")
        private val THRESHOLD_GENERALIZED_TIME = Instant.parse("2050-01-01T00:00:00Z")
    }

    override fun encodeToTlv(): Asn1Primitive =
        when (format) {
            Format.UTC -> instant.encodeToAsn1UtcTimePrimitive()
            Format.GENERALIZED -> instant.encodeToAsn1GeneralizedTimePrimitive()
        }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Asn1Time

        if (instant != other.instant) return false
        if (format != other.format) return false

        return true
    }

    override fun hashCode(): Int {
        var result = instant.hashCode()
        result = 31 * result + format.hashCode()
        return result
    }

    override fun toString(): String {
        return "Asn1Time(instant=$instant, format=$format)"
    }

    /**
     * Enum of supported Time formats
     */
    enum class Format {
        /**
         * UTC TIME
         */
        UTC,

        /**
         * GENERALIZED TIME
         */
        GENERALIZED
    }
}

/**
 * String serializer for [Asn1Time] used for interoperability with non-DER serialization formats.
 *
 * When used with the `awesn1.kxs` DER format, this serializer is bypassed and UTC/GeneralizedTime are
 * encoded/decoded using proper DER TLV.
 * In non-DER formats this serializer stores only the [Instant], so the original UTC-vs-Generalized
 * ASN.1 time choice is not preserved.
 */
internal object Asn1TimeSerializer : KSerializer<Asn1Time> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor(ASN1_DESCRIPTOR_TIME, PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: Asn1Time) {
        encoder.encodeString(value.instant.toString())
    }

    override fun deserialize(decoder: Decoder): Asn1Time {
        return Asn1Time(Instant.parse(decoder.decodeString()))
    }
}
