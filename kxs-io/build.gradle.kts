import at.asitplus.gradle.*
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("at.asitplus.awesn1.buildlogic")
}

awesn1Conventions {
    android("at.asitplus.awesn1.kxsio")
    mavenPublish(
        name = "awesn1 kxs-io",
        description = "Awesome Syntax Notation One - kotlinx.io extensions for DER kotlinx.serialization"
    )
}

kotlin {
    awesn1Targets()
    //we cannot currently test this, so it is only enabled for publishing
    project.gradle.startParameter.taskNames.firstOrNull { it.contains("publish") }?.let {
        watchosDeviceArm64()
    }

    sourceSets {
        commonMain {
            dependencies {
                api(project(":io"))
                api(project(":kxs"))
            }
        }
        commonTest {
            kotlin.srcDir(project(":core").layout.projectDirectory.dir("src/sharedTest"))
            dependencies {
                implementation(serialization("json"))
                implementation(project(":oids"))
            }
        }
    }
    jvm {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_17)
            freeCompilerArgs.add("-Xemit-jvm-type-annotations")
        }
    }
    compilerOptions {
        freeCompilerArgs.add("-opt-in=at.asitplus.awesn1.InternalAwesn1Api")
    }
}
