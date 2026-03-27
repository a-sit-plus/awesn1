// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(at.asitplus.awesn1.InternalAwesn1Api::class)

package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.parseAll
import at.asitplus.awesn1.serialization.internal.DerDecoder
import at.asitplus.awesn1.serialization.internal.DerEncoder
import at.asitplus.awesn1.serialization.internal.DerLayoutPlanContext
import kotlinx.serialization.*
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.modules.EmptySerializersModule
import kotlinx.serialization.modules.SerializersModule
import kotlin.jvm.JvmName
import kotlin.reflect.typeOf


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


    override fun <T> decodeFromByteArray(
        deserializer: DeserializationStrategy<T>,
        bytes: ByteArray
    ): T = catchingUnwrapped {
        val layoutPlan = DerLayoutPlanContext(configuration).also { it.prime(deserializer.descriptor) }
        val decoder = DerDecoder(
            if (bytes.isEmpty()) emptyList() else Asn1Element.parseAll(bytes),
            serializersModule = configuration.serializersModule,
            der = this,
            layoutPlan = layoutPlan,
        )
        return decoder.decodeSerializableValue(deserializer)
    }.wrapAs { SerializationException(it) }.getOrThrow()

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
            catchingUnwrapped {
                val layoutPlan = DerLayoutPlanContext(der.configuration).also { it.prime(serializer.descriptor) }
                val encoder = DerEncoder(
                    serializersModule = der.configuration.serializersModule,
                    der = der,
                    layoutPlan = layoutPlan,
                )
                encoder.encodeSerializableValue(serializer, value)
                return encoder.encodeToTLV()
                    .also { if (it.size > 1) throw ImplementationError("DER serializer multiple elements") }
                    .firstOrNull()
            }.wrapAs { SerializationException(it) }.getOrThrow()

    }

    /**
     * Decodes a single TLV [source] using the given [deserializer].
     *
     * @throws SerializationException if descriptor/tag/nullability constraints are violated
     */
    @ExperimentalSerializationApi
    @Throws(SerializationException::class, ImplementationError::class)
    fun <T> decodeFromTlv(deserializer: DeserializationStrategy<T>, source: Asn1Element): T = catchingUnwrapped {
        val layoutPlan = DerLayoutPlanContext(configuration).also { it.prime(deserializer.descriptor) }
        val decoder = DerDecoder(
            listOf(source),
            serializersModule = configuration.serializersModule,
            der = this,
            layoutPlan = layoutPlan,
        )
        return decoder.decodeSerializableValue(deserializer)
    }.wrapAs { SerializationException(it) }.getOrThrow()
}


/**
 * DER format options.
 *
 * @property encodeDefaults if `true`, default-valued properties are encoded.
 * If `false`, default-valued properties are omitted.
 * @property explicitNulls if `true`, nullable properties are encoded as ASN.1 `NULL` by default.
 * If `false`, nullable `null` values are omitted by default.
 * exactly as originally decoded.
 * @property serializersModule serializers used for contextual/open-polymorphic resolution.
 */
data class DerConfiguration(
    val encodeDefaults: Boolean = true,
    val explicitNulls: Boolean = false,
    val serializersModule: SerializersModule = EmptySerializersModule(),
)

/**
 * Builder for [DerConfiguration], used by `DER { ... }`.
 *
 * - [encodeDefaults]: include/exclude default-valued properties.
 * - [explicitNulls]: encode `null` as ASN.1 `NULL` or omit nullable values.
 * - [serializersModule]: module used for contextual/open-polymorphic serializers.
 */
class DerBuilder internal constructor() {
    var encodeDefaults: Boolean = true
    var explicitNulls: Boolean = false
    var serializersModule: SerializersModule = EmptySerializersModule()

    internal fun build() = DerConfiguration(
        encodeDefaults = encodeDefaults,
        explicitNulls = explicitNulls,
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
 */
@ExperimentalSerializationApi
inline fun <reified T> Der.decodeFromDer(source: ByteArray): T =
    decodeFromByteArray(configuration.serializersModule.serializer(typeOf<T>()), source) as T

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

@ExperimentalSerializationApi
object DefaultDer {
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
    }
}