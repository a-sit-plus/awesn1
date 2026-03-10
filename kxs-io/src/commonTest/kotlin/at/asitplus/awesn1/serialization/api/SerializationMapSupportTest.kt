package at.asitplus.awesn1.serialization.api
import at.asitplus.awesn1.io.decodeFromSource
import at.asitplus.awesn1.io.encodeToSink
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import at.asitplus.awesn1.serialization.*


import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestMapSupport by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "Map roundtrip is supported" {
        val plainMap = mapOf(1 to true, 2 to false, 3 to true)
        DER.decodeFromSource<Map<Int, Boolean>>(Buffer().apply { write(
            Buffer().apply { DER.encodeToSink(plainMap, this) }.readByteArray()
        ) }) shouldBe plainMap

        val wrapped = MapInEnvelope(
            prefix = "map-check",
            values = plainMap,
            suffix = listOf(7, 8, 9)
        )

        DER.decodeFromSource<MapInEnvelope>(Buffer().apply { write(
            Buffer().apply { DER.encodeToSink(wrapped, this) }.readByteArray()
        ) }) shouldBe wrapped
    }

    "Nullable map/list ambiguity is rejected unless tagged" {
        val ambiguous = AmbiguousNullableMapThenList(
            maybeMap = null,
            values = listOf(1, 2, 3)
        )
        shouldThrow<SerializationException> {
            Buffer().apply { DER.encodeToSink(ambiguous, this) }.readByteArray()
        }
        shouldThrow<SerializationException> {
            DER.decodeFromSource<AmbiguousNullableMapThenList>(Buffer().apply { write("3000".hexToByteArray()) })
        }

        val taggedWithoutMap = TaggedNullableMapThenList(
            maybeMap = null,
            values = listOf(1, 2, 3)
        )
        val taggedWithMap = TaggedNullableMapThenList(
            maybeMap = mapOf(1 to true),
            values = listOf(1, 2, 3)
        )

        DER.decodeFromSource<TaggedNullableMapThenList>(Buffer().apply { write(
            Buffer().apply { DER.encodeToSink(taggedWithoutMap, this) }.readByteArray()
        ) }) shouldBe taggedWithoutMap
        DER.decodeFromSource<TaggedNullableMapThenList>(Buffer().apply { write(
            Buffer().apply { DER.encodeToSink(taggedWithMap, this) }.readByteArray()
        ) }) shouldBe taggedWithMap
    }
}

@Serializable
data class AmbiguousNullableMapThenList(
    val maybeMap: Map<Int, Boolean>?,
    val values: List<Int>,
)

@Serializable
data class TaggedNullableMapThenList(
    @Asn1Tag(tagNumber = 40u)
    val maybeMap: Map<Int, Boolean>?,
    val values: List<Int>,
)

@Serializable
data class MapInEnvelope(
    val prefix: String,
    val values: Map<Int, Boolean>,
    val suffix: List<Int>,
)
