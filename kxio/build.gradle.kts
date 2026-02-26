import at.asitplus.gradle.*


plugins {
    id("at.asitplus.awesn1.buildlogic")
}

signumConventions {
    android("at.asitplus.awesn1.kxio")
    mavenPublish(
        name = "awesn1 kxio",
        description = "Awesome Syntax Notation One - kotlix.io addons"
    )
}

kotlin {
    indispensableTargets()
    //we cannot currently test this, so it is only enabled for publishing
    project.gradle.startParameter.taskNames.firstOrNull { it.contains("publish") }?.let {
        watchosDeviceArm64()
    }


    sourceSets {
        commonMain {
            dependencies {
                api(libs.kotlinx.io.core)
                api(project(":core"))
            }
        }
    }
    compilerOptions {
        freeCompilerArgs.add("-Xemit-jvm-type-annotations")
    }

}

exportXCFramework(
    "Awesn1Core",
    transitiveExports = false,
    static = false,
    serialization("json"),

    )
