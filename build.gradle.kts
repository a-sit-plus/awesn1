import at.asitplus.gradle.dokka
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
    kotlin("plugin.serialization") version kotlinVer apply false
    id("com.android.kotlin.multiplatform.library") version libs.versions.agp.get() apply (false)
    id("de.infix.testBalloon") version testballoonVer apply false
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
    rootProject.dependencies.add("dokka", this)
}

allprojects {
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

tasks.named("check") {
    dependsOn("spotlessCheck")
    dependsOn(subprojects.map { "${it.path}:cyclonedxPublishedBom" })
}

val syncSbomDocs by tasks.register<Sync>("syncSbomDocs") {

    val signLocalRepoArtefacts = System.getenv("SIGN_LOCAL_REPO_ARTEFACTS")?.ifBlank { "false" } == "true"


    group = "documentation"
    description = "Exports CycloneDX SBOMs for all published Maven publications into the docs tree."

    val sbomDocsDir = rootProject.layout.projectDirectory.dir("docs/docs/sbom")
    val sbomIndexFile = rootProject.layout.projectDirectory.file("docs/docs/sbom/index.json")
    val sbomTemplateFile = rootProject.layout.projectDirectory.file("docs/templates/sbom-module.template.md")
    val sbomRendererFile = rootProject.layout.projectDirectory.file("docs/tools/render_sbom_pages.py")
    val sortedProjects = subprojects.sortedBy { it.name }

    if (signLocalRepoArtefacts) {
        dependsOn(sortedProjects.map { project ->
            project.tasks.withType(Sign::class.java)
        })
    }
    inputs.file(sbomTemplateFile)
    inputs.file(sbomRendererFile)

    into(sbomDocsDir)
    sortedProjects.forEach { moduleProject ->
        from(moduleProject.layout.buildDirectory.dir("reports/cyclonedx-publications")) {
            include("*/bom.json", "*/bom.xml", "*/bom.json.asc", "*/bom.xml.asc")
            into("publications/${moduleProject.name}")
        }
    }

    doLast {
        val entries = sortedProjects.flatMap { moduleProject ->
            val publicationRoot = moduleProject.layout.buildDirectory.dir("reports/cyclonedx-publications").get().asFile
            publicationRoot
                .listFiles { file -> file.isDirectory }
                .orEmpty()
                .sortedBy { it.name }
                .map { publicationDir ->
                    val jsonSig = publicationDir.resolve("bom.json.asc").takeIf { it.isFile }?.let {
                        "publications/${moduleProject.name}/${publicationDir.name}/bom.json.asc"
                    }
                    val xmlSig = publicationDir.resolve("bom.xml.asc").takeIf { it.isFile }?.let {
                        "publications/${moduleProject.name}/${publicationDir.name}/bom.xml.asc"
                    }
                    mapOf(
                        "module" to moduleProject.name,
                        "publication" to publicationDir.name,
                        "kind" to "publication",
                        "groupId" to rootProject.group.toString(),
                        "version" to rootProject.version.toString(),
                        "json" to "publications/${moduleProject.name}/${publicationDir.name}/bom.json",
                        "xml" to "publications/${moduleProject.name}/${publicationDir.name}/bom.xml",
                        "jsonSig" to (jsonSig ?: ""),
                        "xmlSig" to (xmlSig ?: ""),
                        "mavenCentralClassifier" to "cyclonedx",
                    )
                }
        }
        val sbomModulesDir = sbomDocsDir.dir("modules").asFile
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
                    val fieldComma = if (fieldIndex == entry.size - 1) "" else ","
                    appendLine("      \"${field.key}\": \"${field.value}\"$fieldComma")
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
