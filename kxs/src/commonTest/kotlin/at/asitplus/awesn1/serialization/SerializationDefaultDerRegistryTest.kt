package at.asitplus.awesn1.serialization

import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.matrixConfig
import de.infix.testBalloon.framework.core.invocation
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.modules.EmptySerializersModule

@OptIn(ExperimentalSerializationApi::class)
val SerializationDefaultDerRegistryTest by matrixSuite(
    matrixConfig { execution= ExecutionMode.Sequential }
) {
    "Default DER registry rejects new registrations after default DER initialization" {
        DER

        shouldThrow<IllegalStateException> {
            DefaultDer.register(EmptySerializersModule())
        }.message shouldBe
            "Default DER serializers module registry has already been consumed during default DER initialization"
    }
}
