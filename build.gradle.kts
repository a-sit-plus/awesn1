import at.asitplus.gradle.dokka
import groovy.json.JsonSlurper
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.time.Duration

plugins {
    val kotlinVer = System.getenv("KOTLIN_VERSION_ENV")?.ifBlank { null } ?: libs.versions.kotlin.get()
    val testballoonVer = System.getenv("TESTBALLOON_VERSION_OVERRIDE")?.ifBlank { null } ?: libs.versions.testballoon.get()

    alias(libs.plugins.asp)
    alias(libs.plugins.sbombastic)
    alias(libs.plugins.spotless)
    kotlin("multiplatform") version kotlinVer apply false
    kotlin("jvm") version kotlinVer apply false
    kotlin("plugin.serialization") version kotlinVer apply false
    id("com.android.kotlin.multiplatform.library") version libs.versions.agp.get() apply (false)
    id("de.infix.testBalloon") version testballoonVer apply false
    alias(libs.plugins.jmh) apply false
    base
}
group = "at.asitplus.awesn1"

//work around nexus publish bug
val awesn1Version: String by extra
version = awesn1Version

nexusPublishing {
    transitionCheckOptions {
        maxRetries.set(400)
        delayBetween.set(Duration.ofSeconds(20))
    }
    connectTimeout.set(Duration.ofMinutes(15))
    clientTimeout.set(Duration.ofMinutes(40))
}


//end work around nexus publish bug


val dokkaDir = rootProject.layout.buildDirectory.dir("docs")
dokka {
    dokkaPublications.html{
        outputDirectory.set(dokkaDir)
    }
}
subprojects {
    if(name=="benchmarks") return@subprojects
    if(name=="viewer") return@subprojects
    if(name=="internal-utils") return@subprojects
    rootProject.dependencies.add("dokka", this)
}

allprojects {
    if(name=="benchmarks") return@allprojects
    repositories {mavenLocal()}
    apply(plugin = "org.jetbrains.dokka")
    group = rootProject.group
}

val spdxHeaderLines = listOf(
    "// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH",
    "// SPDX-License-Identifier: Apache-2.0",
)
val spdxHeader = spdxHeaderLines.joinToString(separator = "\n", postfix = "\n\n")
val spdxHeaderExtensions = listOf("kt", "java", "kts", "js", "ts", "swift", "c", "h")
val spdxHeaderSourcePatterns = spdxHeaderExtensions.flatMap { extension ->
    listOf(
        "**/src/main/**/*.$extension",
        "**/src/*Main/**/*.$extension",
    )
}
val spdxHeaderSources = fileTree(rootDir) {
    include(spdxHeaderSourcePatterns)
    exclude("docs/**", "repo/**", "**/build/**", ".gradle/**")
}

spotless {
    format("mainSourceHeaders") {
        target(spdxHeaderSources)
        licenseHeader(
            spdxHeader,
            "^(package|@file:|import|plugins|pluginManagement|dependencyResolutionManagement|rootProject|include|buildscript)",
        )
    }
}

tasks.named("spotlessCheck") {
    dependsOn(subprojects.filterNot { it.name in setOf("benchmarks", "viewer") }.map { "${it.path}:cyclonedxPublishedBom" })
}

val syncSbomDocs by tasks.register("syncSbomDocs") {
    group = "documentation"
    description = "Exports CycloneDX SBOMs for all published Maven publications into the docs tree."

    val sbomDocsDir = rootProject.layout.projectDirectory.dir("docs/docs/sbom")
    val sbomIndexFile = rootProject.layout.projectDirectory.file("docs/docs/sbom/index.json")
    val sbomTemplateFile = rootProject.layout.projectDirectory.file("docs/templates/sbom-module.template.md")
    val sbomRendererFile = rootProject.layout.projectDirectory.file("docs/tools/render_sbom_pages.py")
    val sortedProjects = subprojects.filterNot { it.name in setOf("benchmarks", "viewer") }.sortedBy { it.name }
    val publicationNames = listOf(
        "android",
        "androidNativeArm32",
        "androidNativeArm64",
        "androidNativeX64",
        "androidNativeX86",
        "js",
        "jvm",
        "kotlinMultiplatform",
        "linuxArm64",
        "linuxX64",
        "mingwX64",
        "wasmJs",
    )
    val bomJsonFiles = sortedProjects.flatMap { moduleProject ->
        publicationNames.map { publicationName ->
            moduleProject.layout.buildDirectory.file("reports/cyclonedx-publications/$publicationName/bom.json")
        }
    }

    dependsOn(sortedProjects.flatMap { moduleProject ->
        publicationNames.map { publicationName ->
            "${moduleProject.path}:cyclonedx${publicationName.replaceFirstChar { it.uppercase() }}PublicationBomNormalized"
        }
    })
    inputs.files(bomJsonFiles)
    inputs.file(sbomTemplateFile)
    inputs.file(sbomRendererFile)
    outputs.file(sbomIndexFile)
    outputs.dir(sbomDocsDir.dir("modules"))

    doLast {
        val mavenCentralBaseUrl = "https://repo1.maven.org/maven2"
        val entries = sortedProjects.flatMap { moduleProject ->
            val publicationRoot = moduleProject.layout.buildDirectory.dir("reports/cyclonedx-publications").get().asFile
            publicationNames.map { publicationName ->
                val bomJsonFile = publicationRoot.resolve("$publicationName/bom.json")
                check(bomJsonFile.isFile) {
                    "Expected normalized CycloneDX SBOM at $bomJsonFile for ${moduleProject.path} publication " +
                        "'$publicationName'"
                }

                @Suppress("UNCHECKED_CAST")
                val bom = JsonSlurper().parse(bomJsonFile) as Map<String, Any?>
                @Suppress("UNCHECKED_CAST")
                val metadata = bom["metadata"] as? Map<String, Any?> ?: emptyMap()
                @Suppress("UNCHECKED_CAST")
                val component = metadata["component"] as? Map<String, Any?> ?: emptyMap()
                val groupId = component["group"]?.toString().orEmpty()
                val artifactId = component["name"]?.toString().orEmpty()
                val version = component["version"]?.toString().orEmpty()
                val purl = component["purl"]?.toString().orEmpty()
                val packaging = Regex("[?&]type=([^&]+)").find(purl)?.groupValues?.get(1).orEmpty()
                val artifactBase = buildString {
                    append(mavenCentralBaseUrl)
                    append("/")
                    append(groupId.replace('.', '/'))
                    append("/")
                    append(artifactId)
                    append("/")
                    append(version)
                    append("/")
                    append(artifactId)
                    append("-")
                    append(version)
                    append("-cyclonedx")
                }
                val jsonUrl = "$artifactBase.json"
                val xmlUrl = "$artifactBase.xml"

                linkedMapOf(
                    "module" to moduleProject.name,
                    "publication" to publicationName,
                    "kind" to if (publicationName == "kotlinMultiplatform") "metadata" else "target",
                    "groupId" to groupId,
                    "artifactId" to artifactId,
                    "version" to version,
                    "packaging" to packaging,
                    "json" to jsonUrl,
                    "xml" to xmlUrl,
                    "jsonSig" to "$jsonUrl.asc",
                    "xmlSig" to "$xmlUrl.asc",
                    "mavenCentralClassifier" to "cyclonedx",
                )
            }
        }
        check(entries.isNotEmpty()) {
            "No normalized CycloneDX SBOMs were found; refusing to generate empty SBOM docs."
        }
        val sbomModulesDir = sbomDocsDir.dir("modules").asFile
        sbomDocsDir.dir("publications").asFile.deleteRecursively()
        sbomModulesDir.deleteRecursively()
        sbomModulesDir.mkdirs()

        val json = buildString {
            appendLine("{")
            appendLine("  \"format\": \"CycloneDX\",")
            appendLine("  \"version\": 1,")
            appendLine("  \"entries\": [")
            entries.forEachIndexed { index, entry ->
                val comma = if (index == entries.lastIndex) "" else ","
                appendLine("    {")
                entry.entries.forEachIndexed { fieldIndex, field ->
                    val escapedValue = field.value
                        .replace("\\", "\\\\")
                        .replace("\"", "\\\"")
                    val fieldComma = if (fieldIndex == entry.size - 1) "" else ","
                    appendLine("      \"${field.key}\": \"$escapedValue\"$fieldComma")
                }
                appendLine("    }$comma")
            }
            appendLine("  ]")
            appendLine("}")
        }

        sbomIndexFile.asFile.parentFile.mkdirs()
        sbomIndexFile.asFile.writeText(json)
        val process = ProcessBuilder(
                "python3",
                sbomRendererFile.asFile.absolutePath,
                "--index",
                sbomIndexFile.asFile.absolutePath,
                "--template",
                sbomTemplateFile.asFile.absolutePath,
                "--output-dir",
                sbomModulesDir.absolutePath,
            )
            .directory(rootDir)
            .inheritIO()
            .start()
        val exitCode = process.waitFor()
        check(exitCode == 0) {
            "SBOM module page rendering failed with exit code $exitCode"
        }
    }
}

tasks.register<Copy>("copyChangelog") {
    into(rootDir.resolve("docs/docs"))
    from("CHANGELOG.md")
    doLast {
        val prefix = """
            ---
            hide:
              - navigation
            ---
            
            
        """.trimIndent()
        val path = File("docs/docs/CHANGELOG.md").toPath()
        val original = Files.readString(path, StandardCharsets.UTF_8)
        Files.writeString(path, prefix + original, StandardCharsets.UTF_8)
    }
}

tasks.register<Copy>("mkDocsPrepare") {
    dependsOn("dokkaGenerate")
    dependsOn("copyChangelog")
    dependsOn(":viewer:copyViewerToDocs")
    dependsOn(syncSbomDocs)
    dependsOn("generateAsn1JsDocInputs")
    dependsOn(":core:generateAsn1JsManifest")
    into(rootDir.resolve("docs/docs/dokka"))
    from(dokkaDir)
}

tasks.register("generateAsn1JsDocInputs") {
    group = "documentation"
    description = "Generates ASN1JS docs sample input files from core and kxs test snippets."
    dependsOn(":core:jvmDocsSamplesTest")
    dependsOn(":kxs:generateAsn1JsDocInput")
}

tasks.register<Exec>("mkDocsBuild") {
    dependsOn(tasks.named("mkDocsPrepare"))
    dependsOn(syncSbomDocs)
    workingDir("${rootDir}/docs")
    commandLine("mkdocs", "build", "--clean", "--strict")
}

tasks.register<Copy>("mkDocsSite") {
    dependsOn("mkDocsBuild")
    into(rootDir.resolve("docs/site/assets/images/social"))
    from(rootDir.resolve("docs/docs/assets/images/social"))
}
