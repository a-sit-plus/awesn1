package at.asitplus.awesn1.serialization

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.modules.EmptySerializersModule

@OptIn(ExperimentalSerializationApi::class)
val SerializationDefaultDerRegistryTest by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "Default DER registry rejects new registrations after default DER initialization" {
        DER

        shouldThrow<IllegalStateException> {
            DefaultDer.register(EmptySerializersModule())
        }.message shouldBe
            "Default DER serializers module registry has already been consumed during default DER initialization"
    }
}
