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
    jmh(libs.bouncycastle.prov)
    jmh(libs.bouncycastle.pkix)
}

jmh {
    jmhVersion.set(libs.versions.jmh.get())
    warmupIterations.set(3)
    iterations.set(5)
    fork.set(1)
    // measure average time per operation in microseconds (decode/encode of one fixture == one op)
    benchmarkMode.set(listOf("avgt"))
    timeUnit.set("us")
    // hand the real-world DER/PEM corpus location to the forked JMH JVM (read from the filesystem at runtime)
    jvmArgsAppend.set(
        listOf("-Dawesn1.bench.corpus=${project(":crypto").file("src/jvmTest/resources").absolutePath}")
    )
}
