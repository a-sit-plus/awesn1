import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.MatrixTestDefaults
import de.infix.testBalloon.framework.core.TestSession
import de.infix.testBalloon.framework.core.testScope
import kotlin.time.Duration.Companion.minutes

//Supercharge tests with concurrency!
class ModuleTestSession : TestSession(
    testConfig = DefaultConfiguration
        .testScope(isEnabled = false, timeout = 20.minutes).apply {
            MatrixTestDefaults {
                execution = ExecutionMode.Concurrent(1024)
            }
        }
)