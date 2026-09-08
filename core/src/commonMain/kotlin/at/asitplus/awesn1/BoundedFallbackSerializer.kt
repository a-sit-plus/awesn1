// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Default character limit for a [BoundedFallbackSerializer] whose decode is cheap enough that only the platform
 * bounds it: 384 MiB.
 *
 * A structural ceiling, not a policy budget. Kotlin/JS caps strings at roughly 512 MiB (V8's `2^29 - 24`
 * characters), which is the tightest limit across the supported targets; the JVM, Kotlin/Native and Kotlin/Wasm all
 * index arrays and strings with an `Int` and cap out near 2 GiB. 384 MiB stays below the JS ceiling on every target,
 * so exceeding it is refused with a [SerializationException] instead of a platform-level
 * `OutOfMemoryError: Requested array size exceeds VM limit` or `RangeError: Invalid string length`, neither of which
 * is catchable through the library's own error types.
 *
 * Serializers whose decode costs a large multiple of their input carry a tighter default of their own; see
 * [BoundedFallbackSerializer].
 */
const val DEFAULT_FALLBACK_DECODING_LIMIT: Int = 384 * 1024 * 1024

/**
 * A [KSerializer] for a non-DER fallback representation, bounded by a character limit on the encoded string it
 * accepts while decoding.
 *
 * These serializers are what generic formats such as JSON or CBOR use for awesn1's types; with the `awesn1.kxs` DER
 * format they are bypassed in favour of native DER TLV encoding/decoding, and [at.asitplus.awesn1.serialization.Der]'s
 * `maxInputLength` bounds that path instead.
 *
 * ## The limit is not an input budget
 *
 * [decodingLimit] only bounds what a single value may inflate into *inside* awesn1. It cannot bound the string
 * itself: the format has already materialised it by the time [deserialize] is called. **Bounding the transport and
 * the document remains the caller's responsibility**, exactly as for DER (see
 * [Hardening → Input-Bounding as the Caller's Responsibility](https://a-sit-plus.github.io/awesn1/hardening/#input-bounding-as-the-callers-responsibility)).
 *
 * ## Defaults differ per type, because the cost does
 *
 * Measured against 1 MiB of hostile input, decoding a value costs between 0.5x and 224x its own size in transient
 * allocation, and the expensive cases are expensive for different reasons — memory for an OBJECT IDENTIFIER's one
 * `VarUInt` per node, quadratic CPU for a decimal INTEGER. A single number cannot serve that spread, so each
 * serializer sets its own default:
 *
 * | Serializer                                | Default             | Why                                     |
 * |-------------------------------------------|---------------------|-----------------------------------------|
 * | [Asn1TimeSerializer]                      | 64                  | fixed-shape timestamp                   |
 * | [ObjectIdentifierStringSerializer]        | 4 KiB               | ~224x transient, ~22x retained          |
 * | [Asn1RealStringSerializer]                | 32 KiB              | ~9x transient                           |
 * | [Asn1IntegerDecimalStringSerializer]      | 32 KiB              | decimal conversion is quadratic         |
 * | everything else                           | 384 MiB             | <= 3x, so only the platform bounds it   |
 *
 * Each of those is a `var`: raise it where an application legitimately needs to, lower it wherever untrusted input
 * is a concern.
 *
 * ## Setting the limit
 *
 * Two knobs, covering two disjoint sets of call sites:
 *
 * - [BoundedFallbackSerializer.defaultDecodingLimit], and the per-serializer `decodingLimit` properties, apply to
 *   the singletons, and are read on each decode rather than captured at initialisation. These are the only knobs
 *   that reach a serializer resolved through `@Serializable(with = …)` on a property, including properties declared
 *   by awesn1 itself, such as the [Asn1Element]-typed fields of the PKI types.
 * - [bounded] creates an independently bounded instance for a call site that names its serializer explicitly, either
 *   at the call (`Json.decodeFromString(Asn1ElementFallbackBase64Serializer.bounded(64 * 1024), json)`) or through a
 *   [kotlinx.serialization.modules.SerializersModule].
 */
interface BoundedFallbackSerializer<T> : KSerializer<T> {

    /**
     * Maximum number of characters accepted from the decoder for a single value. Read on every decode, so setting it
     * is not sensitive to when the serializer was initialised.
     */
    val decodingLimit: Int

    /**
     * Decodes one value from its non-DER encoded form, which [deserializeBounded] has already length-checked.
     *
     * Implement the decode here rather than in [deserialize], so that it stays reachable through [bounded] and
     * through a DER-aware [deserialize] override.
     */
    fun decodeBounded(encoded: String): T

    /**
     * Reads one string from [decoder], enforces [decodingLimit] on it, and decodes it via [decodeBounded].
     *
     * The check runs before [decodeBounded], so an over-long value costs nothing beyond the string the format had
     * already built.
     *
     * Whatever [decodeBounded] throws surfaces as a [SerializationException] with the original as its cause. This
     * is the contract kotlinx.serialization decoders owe their callers, and it matters more here than it looks:
     * [Asn1Exception] extends [Throwable] rather than [Exception], so a host's `catch (e: Exception)` around
     * `decodeFromString` would not otherwise catch a malformed value at all. Fatal throwables — cancellation, and
     * the platform's own errors — still propagate untouched.
     *
     * @throws SerializationException if the encoded value exceeds [decodingLimit] characters, or if decoding it fails
     */
    fun deserializeBounded(decoder: Decoder): T {
        val encoded = decoder.decodeString()
        if (encoded.length > decodingLimit) throw SerializationException(
            "Encoded ${descriptor.serialName} exceeds limit: ${encoded.length} > $decodingLimit characters"
        )
        return runWrappingAs(a = { message, cause -> SerializationException(message, cause) }) {
            decodeBounded(encoded)
        }
    }

    override fun deserialize(decoder: Decoder): T = deserializeBounded(decoder)

    /**
     * Encodes one value into its non-DER form, the inverse of [decodeBounded].
     *
     * No limit applies here: the value is already in memory, so encoding it cannot be driven by an attacker. A
     * serializer may still refuse a value it cannot represent losslessly — [Asn1IntegerDecimalStringSerializer]
     * caps the magnitude it will render — and [serializeBounded] turns that refusal into the right exception type.
     */
    fun encodeBounded(value: T): String

    /**
     * Encodes [value] via [encodeBounded] and writes it to [encoder].
     *
     * Whatever [encodeBounded] throws surfaces as a [SerializationException] with the original as its cause, for the
     * same reason it does on the way in: an [Asn1Exception] is not an [Exception], so it would otherwise escape a
     * host's `catch`. Fatal throwables still propagate untouched.
     *
     * @throws SerializationException if [value] cannot be encoded
     */
    fun serializeBounded(encoder: Encoder, value: T) {
        encoder.encodeString(
            runWrappingAs(a = { message, cause -> SerializationException(message, cause) }) { encodeBounded(value) }
        )
    }

    override fun serialize(encoder: Encoder, value: T) = serializeBounded(encoder, value)

    /**
     * Returns a serializer equivalent to this one, but bounded at [decodingLimit] characters instead of tracking
     * this serializer's own limit. The descriptor is unchanged, so serial names and the wire format stay the same.
     *
     * The result decodes the **non-DER** representation unconditionally. Serializers that dispatch on the decoder to
     * support both DER and a fallback — the [Asn1String] family, for instance — lose that dispatch here, so use a
     * bounded instance with the format it was made for. The DER path is bounded by `maxInputLength` regardless.
     */
    fun bounded(decodingLimit: Int): BoundedFallbackSerializer<T> = ReboundedFallbackSerializer(this, decodingLimit)

    companion object {
        /**
         * Character limit applied by every [BoundedFallbackSerializer] that neither sets a tighter default of its own
         * nor was created by [bounded]. Defaults to [DEFAULT_FALLBACK_DECODING_LIMIT]. Only affects non-DER formats.
         */
        var defaultDecodingLimit: Int = DEFAULT_FALLBACK_DECODING_LIMIT
    }
}

/** [BoundedFallbackSerializer.bounded]'s result: the delegate's decode, this instance's limit. */
private class ReboundedFallbackSerializer<T>(
    private val delegate: BoundedFallbackSerializer<T>,
    override val decodingLimit: Int,
) : BoundedFallbackSerializer<T> {
    override val descriptor: SerialDescriptor get() = delegate.descriptor
    override fun decodeBounded(encoded: String): T = delegate.decodeBounded(encoded)
    override fun encodeBounded(value: T): String = delegate.encodeBounded(value)
    override fun bounded(decodingLimit: Int): BoundedFallbackSerializer<T> =
        ReboundedFallbackSerializer(delegate, decodingLimit)
}
