import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldNotBe
import de.infix.testBalloon.framework.core.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.core.testScope

val Test  by matrixSuite {

    "This dummy test" {
        "is just making sure" shouldNotBe "that tests are indeed running"
    }
}
