package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.Asn1String
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.invocation
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestAsn1String by matrixSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "String" {
        val str = Asn1String.UTF8("foo")
        val serialized = DER.encodeToByteArray(str)

        DER.decodeFromByteArray<Asn1String>(serialized) shouldBe str
        DER.decodeFromByteArray<Asn1String.UTF8>(serialized) shouldBe str
    }
}
