import at.asitplus.testballoon.PropertyTest
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldNotBe
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.invocation
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.core.testScope

val Test  by testSuite {

    "This dummy test" {
        "is just making sure" shouldNotBe "that tests are indeed running"
    }
}

//Supercharge tests with concurrency!
class ModuleTestSession : TestSession(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Concurrent)
        .testScope(isEnabled = false, timeout = 20.minutes)
) {
    init {
        PropertyTest.compactByDefault=true
    }
}