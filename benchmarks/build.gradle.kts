import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm")
    kotlin("plugin.serialization")
    alias(libs.plugins.jmh)
}

// Plain JVM benchmark harness (NOT published, NOT part of the KMP target set). Compares awesn1's raw ASN.1 TLV
// layer and its kotlinx.serialization (kxs) certificate decoding against Bouncy Castle. Benchmarks live in
// src/jmh; run with `./gradlew :benchmarks:jmh`.

kotlin {
    jvmToolchain(17)
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
        freeCompilerArgs.add("-opt-in=at.asitplus.awesn1.InternalAwesn1Api")
    }
}

dependencies {
    jmh(project(":core"))
    jmh(project(":kxs"))
    jmh(project(":io")) // for the cache-free streaming encode path (Asn1Element.encodeToDer(kotlinx.io.Sink))
    jmh(project(":crypto")) // for the typed X509Certificate model held by the memory probe
    jmh(libs.bouncycastle.prov)
    jmh(libs.bouncycastle.pkix)
}

jmh {
    jmhVersion.set(libs.versions.jmh.get())
    warmupIterations.set(3)
    warmup.set("10s")
    iterations.set(5)
    timeOnIteration.set("10s")
    fork.set(1)
    jmhTimeout.set("30m")
    // measure average time per operation in microseconds (decode/encode of one fixture == one op)
    benchmarkMode.set(listOf("avgt"))
    timeUnit.set("us")
    // hand the real-world DER/PEM corpus location to the forked JMH JVM (read from the filesystem at runtime)
    jvmArgsAppend.set(
        listOf("-Dawesn1.bench.corpus=${project(":crypto").file("src/jvmTest/resources").absolutePath}")
    )
}

/**
 * Retained-heap probe behind the memory table in `docs/docs/lowlevel.md#memory`. Measures space rather than time, so
 * it is a plain `main` on the JMH source set's classpath instead of a `@Benchmark`. Takes about a minute.
 */
/**
 * Peak heap vs cumulative allocation for a dotted-OID decode, under a deliberately small heap. Distinguishes
 * "this much passed through the allocator" from "this much had to be live at once" — see [OidCostProbe].
 *
 * `./gradlew :benchmarks:oidCostProbe -PoidProbeHeap=32m -PoidProbeChars=5242880`
 */
/**
 * One automated run producing a machine-readable memory report for the OID decode, for a baseline ref **and** HEAD.
 *
 * Answers three different questions with three artefacts per side, because no single one covers them:
 *
 * | file | what it answers | format |
 * |------|-----------------|--------|
 * | `allocations.json` | *what* consumes memory: object class and allocating stack, sampled | JFR → JSON |
 * | `heap-timeline.json` | how used/committed heap moves across the decode | JFR → JSON |
 * | `gc.log` | the same movement per collection, `used-before->used-after(committed)` | text, one line per GC |
 * | `retained-histogram.txt` | exact bytes per class still held after the decode | `jcmd GC.class_histogram` |
 * | `stdout.txt` | the probe's own cumulative and retained figures | text |
 *
 * The histogram is taken while the probe holds its result, so it shows what is *retained*; the transient lists an
 * older implementation built are already garbage by then, which is exactly why `allocations.json` is the one to read
 * for peak composition.
 *
 * ```
 * ./gradlew :benchmarks:oidMemoryReport
 * ./gradlew :benchmarks:oidMemoryReport -PbaselineRef=c3af861 -PoidProbeChars=20971520 -PoidProbeHeap=2g
 * ```
 */
tasks.register("oidMemoryReport") {
    group = "benchmark"
    description = "Machine-readable memory report (allocation profile, heap timeline, retained histogram) for baseline vs HEAD"

    doLast {
        val ref = (project.findProperty("baselineRef") as String?) ?: "development"
        val heap = (project.findProperty("oidProbeHeap") as String?) ?: "512m"
        val chars = (project.findProperty("oidProbeChars") as String?) ?: "5242880"
        val holdSeconds = 25
        val repoRoot = rootProject.layout.projectDirectory.asFile
        val reportRoot = File(
            (project.findProperty("reportDir") as String?) ?: "${repoRoot}/build/reports/oid-memory"
        )

        val javaHome = File(System.getProperty("java.home"))
        fun tool(name: String) = File(javaHome, "bin/$name").takeIf { it.canExecute() }?.absolutePath ?: name

        // `build-logic` is a kotlin-dsl plugin project with no pinned jvmTarget, so its class-file version follows
        // whichever JDK compiles it. A nested `./gradlew` that picks a different JDK than the outer build therefore
        // recompiles it into something the outer daemon cannot load. Pin every child to this build's own JDK.
        fun ProcessBuilder.pinJdk() = apply { environment()["JAVA_HOME"] = System.getProperty("java.home") }

        fun sh(directory: File, vararg command: String): String {
            val process = ProcessBuilder(*command).directory(directory).pinJdk()
                .redirectErrorStream(true).start()
            val out = process.inputStream.bufferedReader().readText()
            process.waitFor()
            return out
        }

        /** Runs the probe in [directory], capturing the artefacts into [outputDir]. */
        fun collect(label: String, directory: File, outputDir: File) {
            outputDir.mkdirs()
            val jfr = File(outputDir, "recording.jfr")
            val gcLog = File(outputDir, "gc.log")
            listOf(jfr, gcLog).forEach { it.delete() }

            val command = listOf(
                "./gradlew", ":benchmarks:oidCostProbe", "--console=plain",
                "-PoidProbeHeap=$heap", "-PoidProbeChars=$chars", "-PoidProbeHold=$holdSeconds",
                "-PoidProbeJfr=${jfr.absolutePath}", "-PoidProbeGcLog=${gcLog.absolutePath}",
            )
            logger.lifecycle("[$label] running probe in ${directory.name} (hold ${holdSeconds}s for the histogram)")

            val process = ProcessBuilder(command).directory(directory).pinJdk()
                .redirectErrorStream(true).start()
            val stdout = StringBuilder()
            var pid: Long? = null
            process.inputStream.bufferedReader().forEachLine { line ->
                stdout.appendLine(line)
                Regex("^pid: +(\\d+)").find(line)?.let { pid = it.groupValues[1].toLong() }
                // fired while the probe still references its result, so the histogram is the retained set
                if (line.startsWith("holding the decoded value")) pid?.let { livePid ->
                    logger.lifecycle("[$label] capturing retained histogram from pid $livePid")
                    File(outputDir, "retained-histogram.txt")
                        .writeText(sh(directory, tool("jcmd"), "$livePid", "GC.class_histogram"))
                }
            }
            process.waitFor()
            File(outputDir, "stdout.txt").writeText(stdout.toString())

            if (jfr.exists()) {
                File(outputDir, "allocations.json").writeText(
                    sh(directory, tool("jfr"), "print", "--json", "--events",
                        "jdk.ObjectAllocationSample,jdk.ObjectAllocationInNewTLAB,jdk.ObjectAllocationOutsideTLAB",
                        jfr.absolutePath)
                )
                File(outputDir, "heap-timeline.json").writeText(
                    sh(directory, tool("jfr"), "print", "--json", "--events",
                        "jdk.GCHeapSummary,jdk.GCHeapConfiguration,jdk.YoungGarbageCollection,jdk.OldGarbageCollection",
                        jfr.absolutePath)
                )
            } else logger.lifecycle("[$label] no JFR recording produced — is this JDK missing Flight Recorder?")
        }

        // baseline first, in its own worktree, built by its own gradlew
        val worktree = File(repoRoot, "build/worktrees/oid-baseline-${ref.replace('/', '-')}")
        if (!worktree.resolve(".git").exists()) {
            logger.lifecycle("creating worktree for $ref at $worktree")
            sh(repoRoot, "git", "worktree", "add", "-f", worktree.absolutePath, ref)
        }
        val probeName = "OidCostProbe.kt"
        File(repoRoot, "benchmarks/src/jmh/kotlin/at/asitplus/awesn1/benchmarks/$probeName").copyTo(
            worktree.resolve("benchmarks/src/jmh/kotlin/at/asitplus/awesn1/benchmarks/$probeName"), overwrite = true
        )
        val baselineBuildFile = worktree.resolve("benchmarks/build.gradle.kts")
        val marker = "// oidCostProbe injected by oidBaselineComparison"
        if (!baselineBuildFile.readText().contains(marker)) baselineBuildFile.appendText(
            """
            |
            |$marker
            |tasks.register<JavaExec>("oidCostProbe") {
            |    mainClass.set("at.asitplus.awesn1.benchmarks.OidCostProbeKt")
            |    classpath = sourceSets["jmh"].runtimeClasspath
            |    jvmArgs("-Xmx" + ((project.findProperty("oidProbeHeap") as String?) ?: "512m"), "-Xms16m")
            |    (project.findProperty("oidProbeChars") as String?)?.let { systemProperty("awesn1.probe.oidChars", it) }
            |    (project.findProperty("oidProbeHold") as String?)?.let { systemProperty("awesn1.probe.holdSeconds", it) }
            |    (project.findProperty("oidProbeGcLog") as String?)?.let {
            |        jvmArgs("-Xlog:gc*,gc+heap=debug:file=" + it + ":time,uptime,level,tags")
            |    }
            |    (project.findProperty("oidProbeJfr") as String?)?.let {
            |        jvmArgs("-XX:StartFlightRecording=filename=" + it + ",settings=profile,dumponexit=true")
            |    }
            |    standardOutput = System.out
            |}
            """.trimMargin()
        )

        collect("baseline $ref", worktree, File(reportRoot, "baseline-${ref.replace('/', '-')}"))
        collect("HEAD", repoRoot, File(reportRoot, "head"))

        logger.lifecycle("")
        logger.lifecycle("report written to $reportRoot")
        reportRoot.walkTopDown().filter { it.isFile }.sorted().forEach {
            logger.lifecycle("  ${it.relativeTo(reportRoot)}  (${it.length()} bytes)")
        }
    }
}

/**
 * Runs [OidCostProbe] against HEAD **and** against a baseline git ref, so a before/after is one command.
 *
 * The baseline is checked out into a git worktree under `build/worktrees/`, the probe source is copied in, and the
 * baseline's own `gradlew` runs it — so the old code is measured by the old build, with only the probe shared. The
 * probe deliberately restricts itself to API that has always existed on `ObjectIdentifier`, which is what makes it
 * runnable against an older tree at all.
 *
 * ```
 * ./gradlew :benchmarks:oidBaselineComparison                       # vs development
 * ./gradlew :benchmarks:oidBaselineComparison -PbaselineRef=c3af861 -PoidProbeHeap=128m
 * ```
 *
 * Worktrees are reused across runs and removed by `oidBaselineClean`.
 */
tasks.register("oidBaselineComparison") {
    group = "benchmark"
    description = "Runs the OID footprint probe against HEAD and against a baseline ref (default: development)"

    doLast {
        val ref = (project.findProperty("baselineRef") as String?) ?: "development"
        val heap = (project.findProperty("oidProbeHeap") as String?) ?: "512m"
        val chars = project.findProperty("oidProbeChars") as String?
        val delay = project.findProperty("oidProbeDelay") as String?
        val hold = project.findProperty("oidProbeHold") as String?
        val gcLog = project.findProperty("oidProbeGcLog") as String?
        val jfr = project.findProperty("oidProbeJfr") as String?
        val side = (project.findProperty("oidProbeSide") as String?) ?: "both"
        require(side in setOf("both", "baseline", "head")) { "oidProbeSide must be both, baseline or head" }
        val repoRoot = rootProject.layout.projectDirectory.asFile
        val worktree = File(repoRoot, "build/worktrees/oid-baseline-${ref.replace('/', '-')}")

        // echoes the child's output line by line as it arrives, so a countdown is visible while it counts.
        // `inheritIO` would hand the child the *daemon's* stdio, which is not where the caller is looking.
        fun runStreaming(directory: File, vararg command: String) {
            val process = ProcessBuilder(*command).directory(directory)
                .apply { environment()["JAVA_HOME"] = System.getProperty("java.home") }
                .redirectErrorStream(true).start()
            process.inputStream.bufferedReader().useLines { lines ->
                lines.forEach { if (it.isNotBlank()) logger.lifecycle(it) }
            }
            require(process.waitFor() == 0) { "`${command.joinToString(" ")}` failed in $directory" }
        }

        fun run(directory: File, vararg command: String): String {
            val process = ProcessBuilder(*command).directory(directory)
                .apply { environment()["JAVA_HOME"] = System.getProperty("java.home") }
                .redirectErrorStream(true).start()
            val output = process.inputStream.bufferedReader().readText()
            require(process.waitFor() == 0) { "`${command.joinToString(" ")}` failed in $directory:\n$output" }
            return output
        }

        val probeName = "OidCostProbe.kt"
        val probeSource = File(repoRoot, "benchmarks/src/jmh/kotlin/at/asitplus/awesn1/benchmarks/$probeName")

        if (side != "head" && !worktree.resolve(".git").exists()) {
            logger.lifecycle("creating worktree for $ref at $worktree")
            run(repoRoot, "git", "worktree", "add", "-f", worktree.absolutePath, ref)
        }

        // the probe is ours, not the baseline's: copy it in, and register the task there if it predates it
        if (side != "head") probeSource.copyTo(
            worktree.resolve("benchmarks/src/jmh/kotlin/at/asitplus/awesn1/benchmarks/$probeName"),
            overwrite = true,
        )
        val baselineBuildFile = worktree.resolve("benchmarks/build.gradle.kts")
        val marker = "// oidCostProbe injected by oidBaselineComparison"
        if (side != "head" && !baselineBuildFile.readText().contains(marker)) baselineBuildFile.appendText(
            """
            |
            |$marker
            |tasks.register<JavaExec>("oidCostProbe") {
            |    mainClass.set("at.asitplus.awesn1.benchmarks.OidCostProbeKt")
            |    classpath = sourceSets["jmh"].runtimeClasspath
            |    jvmArgs("-Xmx" + ((project.findProperty("oidProbeHeap") as String?) ?: "512m"), "-Xms16m")
            |    (project.findProperty("oidProbeChars") as String?)?.let { systemProperty("awesn1.probe.oidChars", it) }
            |    (project.findProperty("oidProbeDelay") as String?)?.let { systemProperty("awesn1.probe.delaySeconds", it) }
            |    (project.findProperty("oidProbeHold") as String?)?.let { systemProperty("awesn1.probe.holdSeconds", it) }
            |    (project.findProperty("oidProbeGcLog") as String?)?.let {
            |        jvmArgs("-Xlog:gc*,gc+heap=debug:file=" + it + ":time,uptime,level,tags")
            |    }
            |    (project.findProperty("oidProbeJfr") as String?)?.let {
            |        jvmArgs("-XX:StartFlightRecording=filename=" + it + ",settings=profile,dumponexit=true")
            |    }
            |    standardOutput = System.out
            |}
            """.trimMargin()
        )

        val arguments = buildList {
            add("./gradlew"); add(":benchmarks:oidCostProbe"); add("-PoidProbeHeap=$heap"); add("--console=plain")
            chars?.let { add("-PoidProbeChars=$it") }
            delay?.let { add("-PoidProbeDelay=$it") }
            hold?.let { add("-PoidProbeHold=$it") }
            // absolute, so the baseline's own working directory does not silently relocate the output
            gcLog?.let { add("-PoidProbeGcLog=${File(it).absolutePath}") }
            jfr?.let { add("-PoidProbeJfr=${File(it).absolutePath}") }
        }
        val interesting = Regex("^(input|outcome|cumulative|peak|live|retained)|^ {2}\\S.*B each")

        // with a profiler attached the countdown and PID must be visible as they happen, so stream that run
        val streaming = delay != null || hold != null

        if (side != "head") {
            logger.lifecycle("")
            logger.lifecycle("=== baseline: $ref (-Xmx$heap) ===")
            if (streaming) runStreaming(worktree, *arguments.toTypedArray())
            else run(worktree, *arguments.toTypedArray()).lines()
                .filter { interesting.containsMatchIn(it) }.forEach { logger.lifecycle(it) }
        }

        if (side != "baseline") {
            logger.lifecycle("")
            logger.lifecycle("=== HEAD (-Xmx$heap) ===")
            if (streaming) runStreaming(repoRoot, *arguments.toTypedArray())
            else run(repoRoot, *arguments.toTypedArray()).lines()
                .filter { interesting.containsMatchIn(it) }.forEach { logger.lifecycle(it) }
        }
    }
}

/** Removes the worktrees [oidBaselineComparison] created. */
tasks.register("oidBaselineClean") {
    group = "benchmark"
    description = "Removes the git worktrees created by oidBaselineComparison"
    doLast {
        val repoRoot = rootProject.layout.projectDirectory.asFile
        File(repoRoot, "build/worktrees").listFiles()?.forEach {
            logger.lifecycle("removing worktree $it")
            ProcessBuilder("git", "worktree", "remove", "--force", it.absolutePath)
                .directory(repoRoot).redirectErrorStream(true).start().waitFor()
        }
        ProcessBuilder("git", "worktree", "prune").directory(repoRoot).start().waitFor()
    }
}

tasks.register<JavaExec>("oidCostProbe") {
    group = "benchmark"
    description = "Reports allocation cost and retained size for decoding a dotted OID string"
    mainClass.set("at.asitplus.awesn1.benchmarks.OidCostProbeKt")
    classpath = sourceSets["jmh"].runtimeClasspath
    val heap = (project.findProperty("oidProbeHeap") as String?) ?: "512m"
    jvmArgs("-Xmx$heap", "-Xms16m")
    (project.findProperty("oidProbeChars") as String?)?.let { systemProperty("awesn1.probe.oidChars", it) }
    (project.findProperty("oidProbeDelay") as String?)?.let { systemProperty("awesn1.probe.delaySeconds", it) }
    (project.findProperty("oidProbeHold") as String?)?.let { systemProperty("awesn1.probe.holdSeconds", it) }

    // Raw heap timeline, because VisualVM's Monitor graph cannot be exported. Either of these gives the same
    // curve as exact, parseable numbers:
    //   -PoidProbeGcLog=gc.log  -> one line per collection with heap before/after
    //   -PoidProbeJfr=probe.jfr -> `jfr print --json --events jdk.GCHeapSummary probe.jfr`
    (project.findProperty("oidProbeGcLog") as String?)?.let {
        jvmArgs("-Xlog:gc*,gc+heap=debug:file=$it:time,uptime,level,tags")
    }
    (project.findProperty("oidProbeJfr") as String?)?.let {
        jvmArgs("-XX:StartFlightRecording=filename=$it,settings=profile,dumponexit=true")
    }

    // a profiler needs to see this process live, so do not swallow its output
    standardOutput = System.out
}

tasks.register<JavaExec>("memoryProbe") {
    group = "benchmark"
    description = "Measures the retained heap of the parsed real-world corpus (raw tree vs. typed kxs model vs. BC)"
    mainClass.set("at.asitplus.awesn1.benchmarks.MemoryProbeKt")
    classpath = sourceSets["jmh"].runtimeClasspath
    // a fixed, roomy heap keeps the collector from resizing mid-measurement
    jvmArgs("-Xms2g", "-Xmx2g")
    systemProperty(
        "awesn1.bench.corpus",
        project(":crypto").file("src/jvmTest/resources").absolutePath,
    )
}
