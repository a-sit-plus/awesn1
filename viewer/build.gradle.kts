import org.gradle.api.publish.maven.tasks.PublishToMavenLocal
import org.gradle.api.publish.maven.tasks.PublishToMavenRepository

plugins {
    id("at.asitplus.awesn1.buildlogic")
}

kotlin {
    js {
        browser { testTask { enabled = false } }
        nodejs()
        binaries.executable()
    }

    sourceSets {
        commonMain.dependencies {
            api(project(":crypto"))
            api(project(":oids"))
        }
    }
}

tasks.withType<PublishToMavenLocal>().configureEach { enabled = false }
tasks.withType<PublishToMavenRepository>().configureEach { enabled = false }

tasks.register<Copy>("copyViewerToDocs") {
    group = "documentation"
    description = "Builds the browser viewer and copies its JavaScript bundle into the MkDocs sources."
    dependsOn("jsBrowserDistribution")
    from(layout.buildDirectory.dir("dist/js/productionExecutable")) {
        include("viewer.js")
        rename("viewer.js", "asn1-viewer.js")
    }
    into(rootProject.layout.projectDirectory.dir("docs/docs/javascripts"))
}
