@file:OptIn(InternalSerializationApi::class)
package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.crypto.BitStringSignatureValue
import at.asitplus.awesn1.crypto.DerDefaults
import at.asitplus.awesn1.crypto.EcdsaSignatureValue
import at.asitplus.awesn1.crypto.GenericSignatureValue
import at.asitplus.awesn1.crypto.SignatureValue
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.modules.EmptySerializersModule

@OptIn(ExperimentalSerializationApi::class)
val SerializationDefaultDerRegistryTest by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    DerDefaults.registerDerSerializers()

    "Default DER round-trips bit string signature values through SignatureValue after explicit registration" {
        val value: GenericSignatureValue = BitStringSignatureValue(
            Asn1BitString(byteArrayOf(0x01, 0x23, 0x45))
        )

        DER.decodeFromByteArray<GenericSignatureValue>(
            DER.encodeToByteArray<GenericSignatureValue>(value)
        ) shouldBe value
    }

    "Default DER round-trips ECDSA signature values through SignatureValue after explicit registration" {
        val value: GenericSignatureValue = EcdsaSignatureValue(
            r = Asn1Integer(1) as Asn1Integer.Positive,
            s = Asn1Integer(2) as Asn1Integer.Positive,
        )

        DER.decodeFromByteArray<GenericSignatureValue>(
            DER.encodeToByteArray<GenericSignatureValue>(value)
        ) shouldBe value
    }

    "Registering a default DER serializers module after default DER initialization throws" {
        DER

        shouldThrow<IllegalStateException> {
            DefaultDerSerializersModuleRegistry.register(EmptySerializersModule())
        }.message shouldBe
            "Default DER serializers module registry has already been consumed during default DER initialization"
    }
}
