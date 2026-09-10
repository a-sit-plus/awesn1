// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(at.asitplus.awesn1.InternalAwesn1Api::class)

package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.serialization.internal.DerDecoder
import at.asitplus.awesn1.serialization.internal.DerEncoder
import at.asitplus.awesn1.serialization.internal.DerDepthGuard
import at.asitplus.awesn1.serialization.internal.DerLayoutPlanContext
import kotlinx.serialization.*
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.modules.EmptySerializersModule
import kotlinx.serialization.modules.SerializersModule
import kotlin.jvm.JvmName
import kotlin.reflect.typeOf

private const val DEFAULT_MAX_NESTING_DEPTH = 32
private const val MAX_NESTING_DEPTH = 65_536

/**
 * Marker format type for ASN.1 DER serialization via kotlinx.serialization.
 *
 * Use the top-level [at.asitplus.awesn1.serialization.api.DER] instance
 * or create a custom instance through `DER { }`.
 */
@OptIn(InternalAwesn1Api::class)
class Der internal constructor(
    val configuration: DerConfiguration = DerConfiguration()
) : BinaryFormat {
    override val serializersModule: SerializersModule
        get() = configuration.serializersModule

    override fun <T> encodeToByteArray(
        serializer: SerializationStrategy<T>,
        value: T
    ): ByteArray = encodeToTlv(serializer, value)?.derEncoded ?: byteArrayOf()


    /**
     * Decodes [bytes] as DER using [deserializer].
     *
     * The configured [DerConfiguration.maxInputLength] is the maximum allowed total number of encoded DER bytes to
     * consume. This limit is enforced before reading or peeking from the underlying source.
     *
     * @throws SerializationException if the input does not parse as DER or violates descriptor/tag/nullability constraints.
     */
    override fun <T> decodeFromByteArray(
        deserializer: DeserializationStrategy<T>,
        bytes: ByteArray
    ): T = runWrappingAs(a = ::SerializationException) {
        val layoutPlan = DerLayoutPlanContext(configuration).also { it.prime(deserializer.descriptor) }
        val decoder = DerDecoder(
            if (bytes.isEmpty()) emptyList() else listOf(
                Asn1Element.parse(source = bytes, limit = configuration.maxInputLength)
            ),
            der = this,
            layoutPlan = layoutPlan,
        )
        return decoder.decodeSerializableValue(deserializer)
    }

    /**
     * Encodes [value] with the given [serializer] into a single ASN.1 TLV element.
     *
     * **This function returns a nullable [Asn1Element] because encoding `null` may not yield any element depending on configuration
     *
     * @throws SerializationException if descriptor/tag/nullability constraints are violated
     * @throws ImplementationError if serialization produced more than one top-level element
     */
    @ExperimentalSerializationApi
    @Throws(SerializationException::class, ImplementationError::class)
    @JvmName("encodeToTlvNullable")
    fun <T> encodeToTlv(serializer: SerializationStrategy<T>, value: T): Asn1Element? =
        Internal.encodeToTlv(this, serializer, value)

    /**
     * Encodes [value] with the given [serializer] into a single ASN.1 TLV element.
     *
     * @throws SerializationException if descriptor/tag/nullability constraints are violated
     * @throws ImplementationError if serialization produced more than one top-level element
     */
    @ExperimentalSerializationApi
    @Throws(SerializationException::class, ImplementationError::class)
    fun <T : Any> encodeToTlv(serializer: SerializationStrategy<T>, value: T): Asn1Element =
        Internal.encodeToTlv(this, serializer, value)
            ?: throw ImplementationError("DER serializer produced no elements")

    internal object Internal {
        @ExperimentalSerializationApi
        @Throws(SerializationException::class, ImplementationError::class)
        fun <T> encodeToTlv(der: Der, serializer: SerializationStrategy<T>, value: T): Asn1Element? =
            runWrappingAs(a = ::SerializationException) {
                val layoutPlan = DerLayoutPlanContext(der.configuration).also { it.prime(serializer.descriptor) }
                val encoder = DerEncoder(
                    der = der,
                    layoutPlan = layoutPlan,
                )
                encoder.encodeSerializableValue(serializer, value)
                val elements = encoder.encodeToTLV()
                    .also { if (it.size > 1) throw ImplementationError("DER serializer multiple elements") }
                elements.forEach {
                    DerDepthGuard().ensureElementTreeFits(
                        it,
                        der.configuration.maxNestingDepth,
                        serializer.descriptor.serialName,
                    )
                }
                return elements.firstOrNull()
            }

    }

    /**
     * Decodes a single TLV [source] using the given [deserializer].
     *
     * @throws SerializationException if descriptor/tag/nullability constraints are violated
     */
    @ExperimentalSerializationApi
    @Throws(SerializationException::class, ImplementationError::class)
    fun <T> decodeFromTlv(deserializer: DeserializationStrategy<T>, source: Asn1Element): T =
        runWrappingAs(a = ::SerializationException) {
            val layoutPlan = DerLayoutPlanContext(configuration).also { it.prime(deserializer.descriptor) }
            val decoder = DerDecoder(
                listOf(source),
                der = this,
                layoutPlan = layoutPlan,
            )
            return decoder.decodeSerializableValue(deserializer)
        }
}


/**
 * DER format options.
 *
 * @property encodeDefaults if `true`, default-valued properties are encoded.
 * If `false`, default-valued properties are omitted.
 * @property explicitNulls if `true`, nullable properties are encoded as ASN.1 `NULL` by default.
 * If `false`, nullable `null` values are omitted by default.
 * exactly as originally decoded.
 * @property maxInputLength maximum allowed DER byte-array size. Defaults to the platform's conservative array ceiling;
 * lower it when the application or protocol has a smaller bound. Streaming `Source` APIs may use a tighter per-call
 * limit.
 * @property maxNestingDepth maximum structural nesting depth the **typed** encoder/decoder will descend before
 * throwing a [kotlinx.serialization.SerializationException]. The raw parser/encoder are iterative and stack-safe, but
 * kotlinx.serialization's encode/decode contract is recursive descent (`deserialize` -> `decodeSerializableElement` ->
 * `deserialize` -> ...; and the mirror on encode), so a *self-referential* `@Serializable` type that is deeply nested
 * (decoded from deeply nested input, or serialized from a deeply nested in-memory value) would otherwise overflow the
 * call stack with an unrecoverable [StackOverflowError]. A limit chosen within the runtime's actual stack headroom
 * rejects the input with a clean, catchable exception before exhaustion.
 * The default is 32, which is conservative across supported runtimes. Values up to 65,536 are accepted for callers
 * that deliberately provide a larger stack; the caller is responsible for ensuring sufficient platform stack space.
 *
 * **IMPORTANT:** this limit applies only to recursion driven through kotlinx.serialization's encoder/decoder callbacks.
 * Recursion performed inside trusted custom code, including [Asn1Serializable.doDecode], is outside the format's
 * control and is **not bounded by `maxNestingDepth`**. Custom implementations must enforce their own limits.
 * @property serializersModule serializers used for contextual/open-polymorphic resolution.
 */
data class DerConfiguration(
    val encodeDefaults: Boolean = true,
    val explicitNulls: Boolean = false,
    val maxInputLength: Long = defaultMaxByteArrayInputLength,
    val maxNestingDepth: Int = DEFAULT_MAX_NESTING_DEPTH,
    val serializersModule: SerializersModule = EmptySerializersModule(),
) {
    init {
        require(maxInputLength in 0..defaultMaxByteArrayInputLength) {
            "maxInputLength must be between 0 and the platform ByteArray ceiling $defaultMaxByteArrayInputLength"
        }
        require(maxNestingDepth in 1..MAX_NESTING_DEPTH) {
            "maxNestingDepth must be between 1 and $MAX_NESTING_DEPTH"
        }
    }
}

/**
 * Builder for [DerConfiguration], used by `DER { ... }`.
 *
 * - [encodeDefaults]: include/exclude default-valued properties.
 * - [explicitNulls]: encode `null` as ASN.1 `NULL` or omit nullable values.
 * - [serializersModule]: module used for contextual/open-polymorphic serializers.
 * - [maxInputLength] maximum allowed DER byte-array size. The default is platform-specific.
 */
class DerBuilder internal constructor() {
    var encodeDefaults: Boolean = true
    var explicitNulls: Boolean = false

    /**
     * Maximum allowed DER byte-array size before parsing is refused.
     *
     * Defaults to a platform-specific conservative ceiling. Streaming `Source` APIs may apply a tighter limit.
     */
    var maxInputLength: Long = defaultMaxByteArrayInputLength

    /**
     * Maximum structural nesting depth the typed encoder/decoder will descend before throwing a
     * [kotlinx.serialization.SerializationException], instead of overflowing the call stack on a deeply nested
     * recursive `@Serializable` type. Defaults to 32 and can be raised to 65,536 when the runtime stack permits. See
     * [DerConfiguration.maxNestingDepth].
     * This does not bound recursion inside custom serializers or [Asn1Serializable.doDecode].
     */
    var maxNestingDepth: Int = DEFAULT_MAX_NESTING_DEPTH
    var serializersModule: SerializersModule = EmptySerializersModule()

    internal fun build() = DerConfiguration(
        encodeDefaults = encodeDefaults,
        explicitNulls = explicitNulls,
        maxInputLength = maxInputLength,
        maxNestingDepth = maxNestingDepth,
        serializersModule = serializersModule,
    )
}


/**
 * Encodes [value] into a single ASN.1 TLV element using the inferred serializer for [T].
 */
@ExperimentalSerializationApi
@JvmName("encodeToTlvNonNull")
inline fun <reified T : Any> Der.encodeToTlv(value: T): Asn1Element =
    encodeToTlv(configuration.serializersModule.serializer(typeOf<T>()), value)

/**
 * Encodes [value] into a single ASN.1 TLV element using the inferred serializer for [T].
 */
@ExperimentalSerializationApi
inline fun <reified T> Der.encodeToTlv(value: T) =
    encodeToTlv(configuration.serializersModule.serializer(typeOf<T>()), value)


/**
 * Decodes [source] from a single ASN.1 TLV element using the inferred deserializer for [T].
 */
@ExperimentalSerializationApi
inline fun <reified T> Der.decodeFromTlv(source: Asn1Element): T =
    decodeFromTlv(configuration.serializersModule.serializer(typeOf<T>()), source) as T

/**
 * Decodes [source] from DER bytes using the inferred deserializer for [T].
 *
 * The configured [DerConfiguration.maxInputLength] is the maximum allowed total number of encoded DER bytes to consume.
 * This limit is enforced before reading or peeking from the underlying source.
 */
@ExperimentalSerializationApi
inline fun <reified T> Der.decodeFromDer(source: ByteArray): T =
    decodeFromByteArray(configuration.serializersModule.serializer(typeOf<T>()), source) as T

@ExperimentalSerializationApi
inline fun <reified T : WithPemLabel> PemLabelSpec<T>.decodeFromPem(
    source: PemBlock,
    der: Der = DER
): T {
    validate(source)
    return der.decodeFromDer(source.payload)
}


@ExperimentalSerializationApi
inline fun <reified T : WithPemLabel> T.encodeToPemBlock(der: Der = DER): PemBlock =
    PemBlock(pemLabel, payload = der.encodeToByteArray(this))

@ExperimentalSerializationApi
inline fun <reified T : WithPemLabel> T.encodeToPem(der: Der = DER): String = encodeToPemBlock(der).encodeToPem()

interface DerEncoder : Encoder, Asn1DerEncoder {
    val der: Der
}

interface DerDecoder : Decoder, Asn1DerDecoder {
    val der: Der
}

/**
 * Factory for the ASN.1 DER kotlinx-serialization format.
 *
 * @param config optional builder block for DER settings
 * (for example `encodeDefaults`, `explicitNulls`, or `reEmitAsn1Backed`)
 */
fun DER(config: DerBuilder.() -> Unit = {}) =
    DerBuilder()
        .apply(config)
        .build()
        .let { Der(it) }

/**
 * Startup-only configuration for the process-wide [DER] instance.
 *
 * This registry is intentionally not thread-safe or coroutine-safe. Complete all [DefaultDer.register] calls and
 * [DefaultDer.maxInputLength] configuration on one thread before the first access to [DER]. Concurrent configuration
 * or configuration racing first use has undefined behaviour; use a separately configured [Der] instance when the
 * lifecycle cannot be guaranteed.
 */
@ExperimentalSerializationApi
object DefaultDer {
    /**
     * Maximum allowed DER byte-array size for the default [DER] instance.
     *
     * Defaults to a platform-specific conservative ceiling.
     */
    var maxInputLength: Long = defaultMaxByteArrayInputLength
        set(value) {
            require(value in 0..defaultMaxByteArrayInputLength) {
                "maxInputLength must be between 0 and the platform ByteArray ceiling $defaultMaxByteArrayInputLength"
            }
            check(!consumed) {
                "Default DER limit has already been set during default DER initialization"
            }
            field = value
        }
    private val contributors = mutableListOf<SerializersModule>()
    private var consumed = false

    fun register(module: SerializersModule) {
        check(!consumed) {
            "Default DER serializers module registry has already been consumed during default DER initialization"
        }
        contributors += module
    }

    internal fun consumeSerializers(): SerializersModule {
        consumed = true
        return if (contributors.isEmpty()) EmptySerializersModule()
        else SerializersModule { contributors.forEach(::include) }
    }
}

val DER: Der by lazy {
    DER {
        serializersModule = DefaultDer.consumeSerializers()
        maxInputLength = DefaultDer.maxInputLength
    }
}
