import at.asitplus.gradle.*


plugins {
    id("at.asitplus.awesn1.buildlogic")
}

signumConventions {
    android("at.asitplus.awesn1.core")
    mavenPublish(
        name = "awesn1 core",
        description = "Awesome Syntax Notation One - Kotlin Multiplatform ASN.1 Engine"
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
                api(serialization("json"))
            }
        }
        commonTest {
            dependencies {
                implementation(kotest("property"))
                implementation("at.asitplus.signum:indispensable:3.19.3")
                implementation("at.asitplus.signum:indispensable-oids:3.19.3")
            }
        }

    }
    compilerOptions {
        freeCompilerArgs.add("-Xemit-jvm-type-annotations")
    }
sourceSets.forEach {
    println(it.name)
}
    sourceSets.filterNot {
        it.name.startsWith("common")
                || it.name.startsWith("jvm")
                || it.name.startsWith("android")
                || it.name.startsWith("apple")
                || it.name.startsWith("macos")
                || it.name.startsWith("mingw")
                || it.name.startsWith("tvos")
                || it.name.startsWith("watch")
                || it.name.startsWith("linux")
                || it.name.startsWith("ios")
                || it.name.startsWith("web")
    }
        .filter { it.name.endsWith("Main") }.forEach { srcSet ->
            srcSet.kotlin.srcDir("$projectDir/src/nonJvmMain/kotlin")
        }

}

exportXCFramework(
    "Awesn1Core",
    transitiveExports = false,
    static = false,
    serialization("json"),

    )
