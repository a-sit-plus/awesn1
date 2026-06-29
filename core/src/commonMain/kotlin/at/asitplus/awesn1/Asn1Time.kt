// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(InternalAwesn1Api::class)

package at.asitplus.awesn1

import at.asitplus.awesn1.Asn1Time.Companion.invoke
import at.asitplus.awesn1.Asn1Time.Fractional.Companion.FRACTIONAL_SECONDS
import at.asitplus.awesn1.encoding.*
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
 * ASN.1 TIME (required since GENERALIZED TIME and UTC TIME exist).
 *
 * The concrete subtype — [SecondsCapped] vs [Fractional] — is the **single source of truth** for whether an
 * encoded fractional second is present:
 *  - [SecondsCapped]: no fractional second (UTC TIME, or GENERALIZED TIME with no `.` fraction).
 *  - [Fractional]: an explicitly encoded fractional second, held verbatim in [Fractional.fractionalSeconds]
 *  (may even be `"0"`; see [Fractional.fractionalSeconds]).
 *
 * Do **not** infer the presence or absence of a fraction from [instant] (or `instant.nanosecondsOfSecond`).
 * [instant] is truncated to nanosecond resolution, so a [Fractional] carrying a sub-nanosecond or all-zero
 * fraction (e.g. `.0000000000001` or `.000`) can report `nanosecondsOfSecond == 0` while still encoding a
 * fraction. Branch on the subtype, never on the instant — using the instant may misclassify cases.
 */
@Serializable(with = Asn1Time.Companion::class)
sealed class Asn1Time : Asn1Encodable<Asn1Primitive> {

    /**
     * The timestamp **value only**, truncated to [Instant]'s nanosecond resolution. For [SecondsCapped] this
     * is whole-second; for [Fractional] it reflects the decoded fraction only up to nanoseconds.
     *
     * This is lossy with respect to the encoding: the exact, arbitrary-precision fraction (which may exceed
     * nanoseconds, or be all zeroes) lives in [Fractional.fractionalSeconds], and whether a fraction is encoded
     * at all is determined by the subtype. Never use [instant] or `instant.nanosecondsOfSecond` to decide
     * whole-second vs fractional — see the class-level note.
     */
    abstract val instant: Instant

    /** Indicates whether this timestamp uses UTC TIME or GENERALIZED TIME. */
    abstract val format: Format

    /**
     * An [Asn1Time] with **no encoded fractional second** (whole-second) — the canonical DER-minimal form, and
     * the only way to construct a time from Kotlin.
     *
     * A value being whole-second is *equivalent to* being a [SecondsCapped]. The converse is **not** true for
     * [Fractional]: a [Fractional] whose value happens to land on a whole second (e.g. an all-zero fraction
     * `.000`) is still a [Fractional], because it encodes differently. Detect "no fraction" via `is SecondsCapped`,
     * never via [instant].
     *
     * @param instant the timestamp to encode; any sub-second part is dropped
     * @param formatOverride force either GENERALIZED TIME or UTC TIME
     */
    class SecondsCapped(instant: Instant, formatOverride: Format? = null) : Asn1Time() {
        override val instant: Instant = Instant.fromEpochSeconds(instant.epochSeconds)
        override val format: Format = formatOverride ?: pickFormat(this.instant)
    }


    /**
     * Returns a fresh instance of a [SecondsCapped] version of this [Asn1Time].
     */
    fun secondsCapped(): SecondsCapped = SecondsCapped(instant)

    /**
     * A GENERALIZED TIME carrying an exact fractional second. Produced **only** by decoding or from a
     * sub-second [Instant]; a whole-second value is always a [SecondsCapped] instead.
     */
    class Fractional internal constructor(
        override val instant: Instant,
        /**
         * Fractional-second digits.
         * Matches [FRACTIONAL_SECONDS] regex: one or more digits. Every digit is significant and preserved,
         * including leading and trailing zeros and an all-zero fraction: `"05"` (0.05 s) ≠ `"5"` (0.5 s),
         * `"120"` is kept verbatim rather than normalized to `"12"`, and `"000"` is kept rather than dropped to ensure
         * even faulty encodings are round-tripped.
         * Although cursed, certificates with such time encodings exist in practice.
         *
         * When derived from an [Instant], trailing zeros are stripped (DER minimum encoding).
         * May carry more precision than [instant]'s nanosecond resolution.
         */
        val fractionalSeconds: String,
    ) : Asn1Time() {

        init {
            require(FRACTIONAL_SECONDS.matches(fractionalSeconds)) {
                "fractionalSeconds must match /${FRACTIONAL_SECONDS.pattern}/ (one or more digits): '$fractionalSeconds'"
            }
        }

        /** Derives the canonical fraction from a sub-second [Instant]: 9-digit nanoseconds, trailing zeros stripped. */
        internal constructor(instant: Instant) : this(
            instant,
            instant.nanosecondsOfSecond.toString().padStart(9, '0').trimEnd('0')
        )

        override val format: Format get() = Format.GENERALIZED

        override fun hashCode(): Int = super.hashCode() * 31 + fractionalSeconds.hashCode()

        override fun equals(other: Any?): Boolean =
            super.equals(other) && other is Fractional && fractionalSeconds == other.fractionalSeconds

        override fun toString(): String = "Asn1Time(instant=$instant, format=$format, fraction=.$fractionalSeconds)"

        companion object {
            /**
             * Fractional-second digits: one or more digits; every digit
             * (incl. leading/trailing/all zeros) is significant.
             */
            val FRACTIONAL_SECONDS = Regex("[0-9]+")
        }
    }

    override fun encodeToTlv(): Asn1Primitive =
        when (this) {
            is Fractional -> {
                val fraction = fractionalSeconds
                val whole = instant.encodeToAsn1Time().dropLast(1) // strip trailing 'Z' -> "YYYYMMDDHHMMSS"
                val body = if (fraction.isEmpty()) whole else "$whole.${fraction}"
                Asn1Primitive(Asn1Element.Tag.TIME_GENERALIZED, "${body}Z".encodeToByteArray())
            }

            is SecondsCapped -> when (format) {
                Format.UTC -> instant.encodeToAsn1UtcTimePrimitive()
                Format.GENERALIZED -> instant.encodeToAsn1GeneralizedTimePrimitive()
            }
        }


    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Asn1Time) return false
        // A SecondsCapped and a Fractional never encode to the same bytes (the latter carries an explicit
        // fraction, even an all-zero one), so they must not compare equal even when their instants coincide.
        if ((this is Fractional) != (other is Fractional)) return false
        return instant == other.instant &&
                format == other.format

    }

    override fun hashCode(): Int {
        var result = instant.hashCode()
        result = 31 * result + format.hashCode()
        return result
    }

    override fun toString(): String = "Asn1Time(instant=$instant, format=$format)"

    companion object : Asn1Serializer<Asn1Primitive, Asn1Time>(
        leadingTags = setOf(Asn1Element.Tag.TIME_UTC, Asn1Element.Tag.TIME_GENERALIZED),
        decodable = object : Asn1Decodable<Asn1Primitive, Asn1Time> {
            @Throws(Asn1Exception::class)
            override fun doDecode(src: Asn1Primitive): Asn1Time =
                if (src.tag == Asn1Element.Tag.TIME_UTC) fromUtc(src.content)
                else decodeGeneralizedTimeToAsn1Time(src.content)
        },
        fallbackSerializer = Asn1TimeSerializer,
    ) {
        override val descriptor: SerialDescriptor =
            PrimitiveSerialDescriptor(ASN1_DESCRIPTOR_TIME, PrimitiveKind.STRING)

        /** Constructs a whole-second [Asn1Time] from an [Instant]. Sub-second precision is dropped (see [SecondsCapped]). */
        operator fun invoke(instant: Instant, formatOverride: Format? = null): Asn1Time {
            return if (instant.nanosecondsOfSecond == 0) SecondsCapped(instant, formatOverride)
            else if (formatOverride == Format.UTC) throw IllegalArgumentException("Cannot construct fractional UTC time")
            else Fractional(instant)
        }

        /**
         * Parses an ASN.1 GENERALIZED TIME value string (`YYYYMMDDHHMMSS[.fraction]Z`) into an [Asn1Time].
         * Unlike [invoke] from an [Instant] — which is bounded by nanosecond resolution — this preserves an
         * **arbitrary-precision** fractional second. Reuses the low-level GENERALIZED TIME string parser.
         */
        @Throws(Asn1Exception::class)
        operator fun invoke(generalizedTime: String): Asn1Time =
            decodeGeneralizedTimeToAsn1Time(generalizedTime.encodeToByteArray())

        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(src: Asn1Primitive, assertTag: Asn1Element.Tag?): Asn1Time {
            verifyTag(src, assertTag)
            return when (assertTag ?: src.tag) {
                Asn1Element.Tag.TIME_UTC -> fromUtc(src.content)
                Asn1Element.Tag.TIME_GENERALIZED -> decodeGeneralizedTimeToAsn1Time(src.content)
                else -> catchingUnwrapped { fromUtc(src.content) }.getOrNull()
                    ?: catchingUnwrapped { decodeGeneralizedTimeToAsn1Time(src.content) }.getOrNull()
                    ?: throw Asn1StructuralException("Unsupported ASN.1 time tag ${assertTag ?: src.tag}")
            }
        }

    }

    /** Enum of supported Time formats */
    enum class Format {
        /** UTC TIME */
        UTC,

        /** GENERALIZED TIME */
        GENERALIZED
    }
}


private val THRESHOLD_UTC_TIME = Instant.parse("1950-01-01T00:00:00Z")
private val THRESHOLD_GENERALIZED_TIME = Instant.parse("2050-01-01T00:00:00Z")


/** RFC 5280 §4.1.2.5 cut-over: times in `[1950,2050)` use UTC TIME, everything else GENERALIZED TIME. */
private fun pickFormat(instant: Instant): Asn1Time.Format =
    if (instant !in THRESHOLD_UTC_TIME..<THRESHOLD_GENERALIZED_TIME) Asn1Time.Format.GENERALIZED
    else Asn1Time.Format.UTC

private fun fromUtc(content: ByteArray): Asn1Time =
    Asn1Time.SecondsCapped(Instant.decodeUtcTimeFromAsn1ContentBytes(content), Asn1Time.Format.UTC)


/**
 * String serializer for [Asn1Time] used for interoperability with non-DER serialization formats.
 *
 * When used with the `awesn1.kxs` DER format, this serializer is bypassed and UTC/GeneralizedTime are
 * encoded/decoded using proper DER TLV.
 * In non-DER formats this serializer stores only nanosecond precision, and the
 * UTC-vs-Generalized choice is not preserved.
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

/**
 * Returns a [Instant] with the same epoch seconds, but nanosecond precision capped
 */
fun Instant.secondsCapped() = Instant.fromEpochSeconds(this.epochSeconds)