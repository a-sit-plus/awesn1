package at.asitplus.awesn1.serialization.api
import at.asitplus.awesn1.io.decodeFromSource
import at.asitplus.awesn1.io.encodeToSink
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import at.asitplus.awesn1.serialization.*


import at.asitplus.awesn1.Asn1OctetString
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.serializer
import kotlin.random.Random

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestWritingSmoke by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "Writing" {
        val descriptor = TypesUmbrella.serializer().descriptor
        for (i in 0 until descriptor.elementsCount) {
            val name = descriptor.getElementName(i)
            val annotations = descriptor.getElementAnnotations(i)
            println("Property '$name' (index $i) annotations: $annotations")
        }

        val derEncoded = Buffer().apply { DER.encodeToSink(
             TypesUmbrella(
                    str = "foo",
                    i = 2u,
                    nullable = null,
                    list = listOf("Foo", "Bar", "Baz"),
                    map = mapOf(3 to false),
                    inner = Simple("simpleton"),
                    innersList = listOf(SimpleOctet("one"), SimpleOctet("three")),
                    byteString = Random.nextBytes(1336),
                    byteArray = Random.nextBytes(1337),
                    innerImpl = SimpleLong(-333L),
                    enum = Baz.BAR,
                    octet = Asn1OctetString("Hello World".encodeToByteArray())
                )
        , this) }.readByteArray()
        println(derEncoded.toHexString())

        val string = "Foo"
        println(
            Buffer().apply { DER.encodeToSink( string, this) }.readByteArray()
                .toHexString())

        println(
            Buffer().apply { DER.encodeToSink(
                
                SimpleLong(666L)
            , this) }.readByteArray().toHexString())
        println(
            Buffer().apply { DER.encodeToSink( 3.141516, this) }.readByteArray()
                .toHexString())
        println(
            Buffer().apply { DER.encodeToSink( Simple("a"), this) }.readByteArray()
                .toHexString())
        println(
            Buffer().apply { DER.encodeToSink(
                
                NumberTypesUmbrella(1, 2, 3.0f, 4.0, true, 'd')
            , this) }.readByteArray().toHexString())
    }
}

@Serializable
data class SimpleLong(val a: Long)

@Serializable
data class Simple(val a: String)

@Serializable
data class SimpleOctet(val a: String)

@Asn1Tag(
    tagNumber = 99u,
    tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
)
@Serializable
enum class Baz {
    FOO,
    BAR,
}

@Serializable
data class TypesUmbrella(
    val inner: Simple,
    @Asn1Tag(
        tagNumber = 333u,
        tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
    )
    val str: String,
    val i: UInt,
    val nullable: Double?,
    val list: List<String>,
    val map: Map<Int, Boolean>,
    val innersList: List<SimpleOctet>,
    val byteString: ByteArray,
    val byteArray: ByteArray,
    val innerImpl: SimpleLong,
    @Asn1Tag(
        tagNumber = 66u,
        tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
    )
    val enum: Baz,
    val octet: Asn1OctetString
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as TypesUmbrella

        if (str != other.str) return false
        if (i != other.i) return false
        if (nullable != other.nullable) return false
        if (list != other.list) return false
        if (map != other.map) return false
        if (inner != other.inner) return false
        if (innersList != other.innersList) return false
        if (!byteString.contentEquals(other.byteString)) return false
        if (!byteArray.contentEquals(other.byteArray)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = str.hashCode()
        result = 31 * result + i.toInt()
        result = 31 * result + (nullable?.hashCode() ?: 0)
        result = 31 * result + list.hashCode()
        result = 31 * result + map.hashCode()
        result = 31 * result + inner.hashCode()
        result = 31 * result + innersList.hashCode()
        result = 31 * result + byteString.contentHashCode()
        result = 31 * result + byteArray.contentHashCode()
        return result
    }
}

@Serializable
data class NumberTypesUmbrella(
    val int: Int,
    val long: Long,
    val float: Float,
    val double: Double,
    val boolean: Boolean,
    val char: Char
)

@Serializable
data class NullableByteString(
    val byteString: ByteArray?
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as NullableByteString

        if (byteString != null) {
            if (other.byteString == null) return false
            if (!byteString.contentEquals(other.byteString)) return false
        } else if (other.byteString != null) return false

        return true
    }

    override fun hashCode(): Int {
        return byteString?.contentHashCode() ?: 0
    }
}
