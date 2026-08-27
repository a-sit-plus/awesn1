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
