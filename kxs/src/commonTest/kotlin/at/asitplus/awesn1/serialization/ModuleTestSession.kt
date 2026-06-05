package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.docs.ConcreteCustomAttribute
import at.asitplus.awesn1.docs.CustomAttribute
import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.MatrixTestDefaults
import de.infix.testBalloon.framework.core.TestSession
import de.infix.testBalloon.framework.core.testScope
import kotlinx.serialization.modules.SerializersModule
import kotlin.time.Duration.Companion.minutes

//Supercharge tests with concurrency!
class ModuleTestSession : TestSession(
    testConfig = DefaultConfiguration
        .testScope(isEnabled = false, timeout = 20.minutes).apply {
            MatrixTestDefaults {
                execution = ExecutionMode.Concurrent(1024)
            }
        }
) {
    init {
        // --8<-- [start:kxs-default-der-registry-setup]
        DefaultDer.register(SerializersModule {
            polymorphicByOid(
                CustomAttribute::class,
                serialName = "TutorialDocCmsAttributeValue",
            ) {
                subtype<ConcreteCustomAttribute>(ConcreteCustomAttribute)
            }
        })
        // --8<-- [end:kxs-default-der-registry-setup]
    }

}