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
