import at.asitplus.gradle.*

plugins {
    id("at.asitplus.awesn1.buildlogic")
}

awesn1Conventions {
    android("at.asitplus.awesn1.crypto")
    mavenPublish(
        name = "awesn1 crypto",
        description = "Awesome Syntax Notation One - structural crypto and PKI models"
    )
}

kotlin {
    awesn1Targets()

    sourceSets {
        commonMain {
            dependencies {
                api(project(":core"))
            }
        }

        commonTest {
            dependencies {
                implementation(project(":kxs"))
            }
        }
    }
}
