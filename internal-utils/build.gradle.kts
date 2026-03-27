import at.asitplus.gradle.*

plugins {
    id("at.asitplus.awesn1.buildlogic")
}

awesn1Conventions {
    android("at.asitplus.awesn1.internals")
    mavenPublish(
        name = "awesn1 internals",
        description = "Awesome Syntax Notation One - utility internals"
    )
}

kotlin {
    awesn1Targets()
    sourceSets {
        val commonMain by getting
        create("nonJvmMain") {
            kotlin.srcDir("$projectDir/src/nonJvmMain/kotlin")
            dependsOn(commonMain)
        }
        filterNot {
            it.name == "nonJvmMain" ||
            sequenceOf("common", "jvm", "android", "apple", "macos", "mingw", "tvos", "watch", "linux", "ios", "web")
                .any { s -> it.name.startsWith(s) }
        }
        .filter { it.name.endsWith("Main") }.forEach { srcSet ->
            srcSet.dependsOn(sourceSets.getByName("nonJvmMain"))
        }
    }
}
