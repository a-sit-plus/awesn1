package at.asitplus.awesn1.serialization.api
import at.asitplus.awesn1.io.decodeFromSource
import at.asitplus.awesn1.io.encodeToSink
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import at.asitplus.awesn1.serialization.*


import at.asitplus.awesn1.Asn1String
import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.matrixConfig
import de.infix.testBalloon.framework.core.invocation
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestAsn1String by matrixSuite(
    matrixConfig { execution= ExecutionMode.Sequential }
) {
    "String" {
        val str = Asn1String.UTF8("foo")
        val serialized = Buffer().apply { DER.encodeToSink(str, this) }.readByteArray()

        DER.decodeFromSource<Asn1String>(Buffer().apply { write(serialized) }) shouldBe str
        DER.decodeFromSource<Asn1String.UTF8>(Buffer().apply { write(serialized) }) shouldBe str
    }
}
