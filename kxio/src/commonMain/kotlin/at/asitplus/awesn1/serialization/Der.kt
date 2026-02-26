package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.encoding.KxIoSink
import at.asitplus.awesn1.encoding.KxIoSource
import kotlinx.io.Sink
import kotlinx.io.Source
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.serializer
import kotlin.reflect.typeOf

fun <T> Der.encodeToSink(serializer: SerializationStrategy<T>, value: T, sink: Sink) {
    encodedEncoder(serializer, value).writeTo(KxIoSink(sink))
}

inline fun <reified T> Der.encodeToSink(
    value: T,
    sink: Sink
): Unit = encodeToSink(configuration.serializersModule.serializer(typeOf<T>()), value, sink)


fun <T> Der.decodeFromSource(deserializer: DeserializationStrategy<T>, source: Source): T =
    configuredDecoder(deserializer, KxIoSource(source)).decodeSerializableValue(deserializer)

inline fun <reified T> Der.decodeFromSource(source: Source): T =
    decodeFromSource(configuration.serializersModule.serializer(typeOf<T>()), source) as T