import at.asitplus.gradle.*
import org.gradle.api.tasks.testing.Test
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("at.asitplus.awesn1.buildlogic")
}

awesn1Conventions {
    android("at.asitplus.awesn1.kxs")
    mavenPublish(
        name = "awesn1 kxs",
        description = "Awesome Syntax Notation One - kotlinx.serialization DER format"
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
                api(project(":core"))
                api(serialization("core"))
            }
        }
        commonTest {
            dependencies {
                implementation(kotest("property"))
                implementation("at.asitplus.testballoon:property:${libs.versions.testballoonAddons.get()}")
                implementation(project(":crypto"))
                implementation(project(":oids"))
                implementation("at.asitplus.signum:indispensable:3.19.3")
                implementation("at.asitplus.signum:indispensable-oids:3.19.3")
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

val jvmDocsSamplesTest by tasks.register<Test>("jvmDocsSamplesTest") {
    group = "verification"
    description = "Runs only kxs docs sample tests used for ASN1JS manifest generation."
    val rawSamplesFile = layout.buildDirectory.file("tmp/asn1js/samples.txt")

    val jvmTest = tasks.named<Test>("jvmTest").get()
    testClassesDirs = jvmTest.testClassesDirs
    classpath = jvmTest.classpath
    systemProperty("awesn1.docs.samples.file", rawSamplesFile.get().asFile.absolutePath)
    useJUnitPlatform()
    filter {
        includeTestsMatching("*SerializationDocumentationTutorial*")
    }
    outputs.upToDateWhen { false }
    doFirst {
        rawSamplesFile.get().asFile.delete()
    }
}

val generateAsn1JsDocInput by tasks.registering {
    group = "documentation"
    description = "Generates kxs ASN1JS docs sample input."
    dependsOn(jvmDocsSamplesTest)
}
