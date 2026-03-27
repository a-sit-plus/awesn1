import at.asitplus.gradle.*
import org.gradle.api.GradleException
import org.gradle.api.tasks.testing.Test
import org.jetbrains.kotlin.gradle.dsl.JvmTarget


plugins {
    id("at.asitplus.awesn1.buildlogic")
}

awesn1Conventions {
    android("at.asitplus.awesn1.core")
    mavenPublish(
        name = "awesn1 core",
        description = "Awesome Syntax Notation One - Kotlin Multiplatform ASN.1 Engine"
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
                api(serialization("core"))
            }
        }
        commonTest {
            dependencies {
                implementation(project(":oids"))
                implementation("at.asitplus.signum:indispensable:3.19.3")
                implementation("at.asitplus.signum:indispensable-oids:3.19.3")
            }
        }
        jvmTest {
            dependencies {
                implementation(project(":kxs"))
                implementation(serialization("json"))
            }
        }
    }
    jvm {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_17)
            freeCompilerArgs.add("-Xemit-jvm-type-annotations")
        }
    }

}

val jvmDocsSamplesTest by tasks.register<Test>("jvmDocsSamplesTest") {
    group = "verification"
    description = "Runs only docs sample tests used for ASN1JS manifest generation."
    val rawSamplesFile = layout.buildDirectory.file("tmp/asn1js/samples.txt")

    val jvmTest = tasks.named<Test>("jvmTest").get()
    testClassesDirs = jvmTest.testClassesDirs
    classpath = jvmTest.classpath
    systemProperty("awesn1.docs.samples.file", rawSamplesFile.get().asFile.absolutePath)
    useJUnitPlatform()
    filter {
        includeTestsMatching("*CoreDocumentationHooks*")
        includeTestsMatching("*SerializationDocumentationTutorial*")
    }
    outputs.upToDateWhen { false }
    doFirst {
        rawSamplesFile.get().asFile.delete()
    }
}

val generateAsn1JsManifest by tasks.registering {
    group = "documentation"
    description = "Runs JVM tests and exports ASN1JS sample payloads for MkDocs links."

    dependsOn(jvmDocsSamplesTest)
    dependsOn(":kxs:generateAsn1JsDocInput")

    val rawSamplesFile = layout.buildDirectory.file("tmp/asn1js/samples.txt")
    val kxsSamplesFile = project(":kxs").layout.buildDirectory.file("tmp/asn1js/samples.txt")
    val outputFile = rootProject.layout.projectDirectory.file("docs/docs/generated/asn1js-links.json")

    inputs.file(rawSamplesFile)
    inputs.file(kxsSamplesFile)
    outputs.file(outputFile)

    doLast {
        val sourceFiles = listOf(rawSamplesFile.get().asFile, kxsSamplesFile.get().asFile)
        sourceFiles.forEach { sourceFile ->
            if (!sourceFile.exists()) {
                throw GradleException("Missing docs samples file at ${sourceFile.absolutePath}")
            }
        }
        val samples = linkedMapOf<String, String>()
        sourceFiles.forEach { sourceFile ->
            sourceFile.forEachLine { line ->
                val trimmed = line.trim()
                if (trimmed.isNotEmpty()) {
                    val parts = trimmed.split('|')
                    if (parts.size != 2) {
                        throw GradleException("Invalid docs sample line: '$line'")
                    }
                    val id = parts[0]
                    val value = parts[1]
                    val previous = samples[id]
                    if (previous != null && previous != value) {
                        throw GradleException("Conflicting ASN1JS sample for id '$id': '$previous' vs '$value'")
                    }
                    samples[id] = value
                }
            }
        }

        if (samples.isEmpty()) {
            throw GradleException("No ASN1JS sample entries found in ${sourceFiles.joinToString { it.absolutePath }}.")
        }

        outputFile.asFile.parentFile.mkdirs()
        val entries = samples.entries.sortedBy { it.key }
        val json = buildString {
            appendLine("{")
            entries.forEachIndexed { index, entry ->
                val comma = if (index == entries.lastIndex) "" else ","
                append("  \"")
                append(entry.key)
                append("\": \"")
                append(entry.value)
                append('"')
                appendLine(comma)
            }
            appendLine("}")
        }
        outputFile.asFile.writeText(json)
        logger.lifecycle("Wrote ${entries.size} ASN1JS samples to ${outputFile.asFile}")
    }
}
