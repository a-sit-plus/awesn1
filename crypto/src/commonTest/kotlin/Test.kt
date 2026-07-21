import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.MatrixTestDefaults
import at.asitplus.awesn1.crypto.UserPrincipalName
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.awesn1.serialization.DefaultDer
import at.asitplus.awesn1.serialization.polymorphicByOid
import de.infix.testBalloon.framework.core.TestSession
import de.infix.testBalloon.framework.core.testScope
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldNotBe
import kotlinx.serialization.modules.SerializersModule
import kotlin.time.Duration.Companion.minutes

val Test by matrixSuite {

    "This dummy test" {
        "is just making sure" shouldNotBe "that tests are indeed running"
    }
}

//Supercharge tests with concurrency!
class ModuleTestSession : TestSession(
    testConfig = DefaultConfiguration
        .testScope(isEnabled = false, timeout = 20.minutes)
        .apply { MatrixTestDefaults { execution = ExecutionMode.Concurrent(1024) } }
) {
    init {
        // --8<-- [start:crypto-x509-other-name-default-der-registration]
        DefaultDer.register(SerializersModule {
            polymorphicByOid(
                X509GeneralName.Other.SemanticValue::class,
                serialName = "X509OtherName",
            ) {
                subtype<UserPrincipalName>(UserPrincipalName)
                catchAll<X509GeneralName.Other.SemanticValue.Generic>()
            }
        })
        // --8<-- [end:crypto-x509-other-name-default-der-registration]
    }
}
