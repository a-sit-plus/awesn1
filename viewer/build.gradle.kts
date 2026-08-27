import at.asitplus.gradle.awesn1Targets
import at.asitplus.gradle.awesn1Conventions
import org.jetbrains.kotlin.gradle.targets.js.ir.KotlinJsIrTarget

plugins {
    id("at.asitplus.awesn1.buildlogic")
}


awesn1Conventions {
    android("at.asitplus.awesn1.viewer")
    mavenPublish(
        name = "awesn1 Viewer",
        description = "Awesome Syntax Notation One - JS Viewer"
    )
}


kotlin {
    awesn1Targets()
    targets.named("js") {
        (this as KotlinJsIrTarget).binaries.executable()
    }
    //we cannot currently test this, so it is only enabled for publishing
    project.gradle.startParameter.taskNames.firstOrNull { it.contains("publish") }?.let {
        watchosDeviceArm64()
    }

    sourceSets {
        commonMain.dependencies {
            api(project(":crypto"))
            api(project(":oids"))
        }
    }
}
