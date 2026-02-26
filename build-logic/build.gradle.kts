plugins {
    `kotlin-dsl`
}

group = "at.asitplus.awesn1.buildlogic"

gradlePlugin {
    plugins {
        create("awesn1Conventions") {
            id = "at.asitplus.awesn1.buildlogic"
            implementationClass = "at.asitplus.gradle.Awesn1ConventionsPlugin"
            displayName = "awesn1 Build Logic Conventions"
            description = "Common build logic for awesn1"
        }
    }
}

dependencies {
    val kotlinVer = System.getenv("KOTLIN_VERSION_ENV")?.ifBlank { null } ?: libs.versions.kotlin.get()

    implementation("org.jetbrains.kotlin.multiplatform:org.jetbrains.kotlin.multiplatform.gradle.plugin:$kotlinVer")
    implementation(libs.agp)
    implementation(libs.asp)
}

repositories {
    maven {
        url = uri("https://raw.githubusercontent.com/a-sit-plus/gradle-conventions-plugin/mvn/repo")
        name = "aspConventions"
    }
    mavenLocal()
    gradlePluginPortal()
    google()
    mavenCentral()
}
