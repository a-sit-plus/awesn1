package at.asitplus.awesn1.encoding

import at.asitplus.awesn1.serialization.Der
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.serializer

/**
 * Encodes [value] with [serializer] and [der], then appends the resulting TLV element.
 *
 * If the configured DER encoding omits [value], such as a nullable `null` when explicit nulls are disabled,
 * nothing is appended.
 *
 * @throws SerializationException if serialization constraints are violated
 */
@Throws(Throwable::class)
fun <Serializable> Asn1TreeBuilder.append(serializer: KSerializer<Serializable>, value: Serializable, der:Der) {
    der.encodeToTlv(serializer, value)?.let { +it }
}

/**
 * Encodes [value] with its inferred serializer and [der], then appends the resulting TLV element.
 *
 * The serializer is inferred from the static type [T], which must have an available kotlinx serializer.
 *
 * @throws SerializationException if serialization constraints are violated
 */
@OptIn(ExperimentalSerializationApi::class)
@Throws(Throwable::class)
inline fun <reified Serializable> Asn1TreeBuilder.append(value: Serializable, der: Der) =
    append(serializer(), value, der)

/**
 * Encodes this value with its inferred serializer and appends it to the current [Asn1TreeBuilder].
 *
 * Both a [Der] context and an [Asn1TreeBuilder] context are required, which allows concise use such as
 * `with(DER) { Asn1.Sequence { +value } }`. Types supported directly by the core builder, including
 * [WrappedElement] and [WrappedEncodable], do not require a [Der] context.
 *
 * @throws SerializationException if serialization constraints are violated
 */
@OptIn(ExperimentalSerializationApi::class)
@Throws(Throwable::class)
context(der:Der,  treeBuilder: Asn1TreeBuilder)
inline operator fun <reified Serializable> Serializable.unaryPlus() {
    treeBuilder.append(this, der)
}
