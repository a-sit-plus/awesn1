package at.asitplus.awesn1.serialization.api
import at.asitplus.awesn1.io.decodeFromSource
import at.asitplus.awesn1.io.encodeToSink
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import at.asitplus.awesn1.serialization.*


import at.asitplus.awesn1.Asn1String
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestAsn1String by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "String" {
        val str = Asn1String.UTF8("foo")
        val serialized = Buffer().apply { DER.encodeToSink(str, this) }.readByteArray()

        DER.decodeFromSource<Asn1String>(Buffer().apply { write(serialized) }) shouldBe str
        DER.decodeFromSource<Asn1String.UTF8>(Buffer().apply { write(serialized) }) shouldBe str
    }
}
