import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.MatrixTestDefaults
import de.infix.testBalloon.framework.core.TestSession
import de.infix.testBalloon.framework.core.testScope
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldNotBe
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
)