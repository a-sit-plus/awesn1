# Software Bill of Materials

Awesome Syntax Notation One publishes CycloneDX SBOMs for every Maven publication of every module.

Each SBOM describes one published Maven artifact, not just one Gradle project. For Kotlin Multiplatform modules that
means there is usually one SBOM for the root `kotlinMultiplatform` publication and one SBOM for each concrete target
publication such as `jvm`, `android`, `iosArm64`, `wasmJs`, and so on.

## Formats

- CycloneDX JSON
- CycloneDX XML

## How To Read The SBOMs

awesn1 publishes publication-oriented SBOMs:

- the `kotlinMultiplatform` SBOM is the root metadata publication SBOM
- target SBOMs such as `jvm`, `android`, `iosArm64`, `iosSimulatorArm64`, `js`, or `wasmJs` describe the concrete
  published target artifacts

This distinction matters when interpreting dependencies:

- a `kotlinMultiplatform` SBOM can legitimately reference metadata-style artifacts such as root modules, metadata
  `jar`s, and `pom` packages, because that publication is itself a metadata publication used for variant selection
- a target SBOM reflects the concrete published target artifact contract, so its root component directly depends on
  the actual published target artifacts for that publication

In practice, this means:

- Android target publications show project-local dependencies such as `core-android`, `io-android`, or `kxs-android`
  as `aar`
- native target publications show concrete target artifacts such as `*-iosarm64` or `*-iossimulatorarm64` as `klib`
- JVM target publications show concrete JVM artifacts as `jar`
- metadata wrapper modules can still appear transitively in a target SBOM when they are real published artifacts in
  the dependency graph

The most useful rule of thumb is:

- use `kotlinMultiplatform` if you want the root KMP metadata publication view
- use a target SBOM if you want the concrete artifact a consumer resolves for that platform

## Maven Central

Each published awesn1 Maven publication attaches its SBOM with the standard `cyclonedx` classifier:

- `artifact-version-cyclonedx.json`
- `artifact-version-cyclonedx.xml`

For a multiplatform module, that means one SBOM pair for each publication such as `kotlinMultiplatform`, `jvm`,
`android`, `js`, `iosArm64`, and so on is created and published.

On Maven Central, look for the normal publication artifact first and then the attached SBOM files with classifier
`cyclonedx`. For example, if a publication is published as `artifact-version.aar`, its SBOMs are published alongside
it as `artifact-version-cyclonedx.json` and `artifact-version-cyclonedx.xml`.

## Documentation Downloads

The documentation site mirrors the publication layout used for publishing and exposes the same per-publication SBOM
files:

- `sbom/publications/<module>/<publication>/bom.json`
- `sbom/publications/<module>/<publication>/bom.xml`
- `sbom/publications/<module>/<publication>/bom.json.asc`
- `sbom/publications/<module>/<publication>/bom.xml.asc`

Examples:

- `core` Kotlin Multiplatform metadata: [JSON]({{ config.site_url }}/sbom/publications/core/kotlinMultiplatform/bom.json), [XML]({{ config.site_url }}/sbom/publications/core/kotlinMultiplatform/bom.xml)
- `core` JVM: [JSON]({{ config.site_url }}/sbom/publications/core/jvm/bom.json), [XML]({{ config.site_url }}/sbom/publications/core/jvm/bom.xml)
- `kxs` JS: [JSON]({{ config.site_url }}/sbom/publications/kxs/js/bom.json), [XML]({{ config.site_url }}/sbom/publications/kxs/js/bom.xml)

Machine-readable index:

- [SBOM index JSON]({{ config.site_url }}/sbom/index.json)

The index is a lightweight discovery document for the documentation export. It lists each module/publication pair and
points to the corresponding JSON and XML SBOM files.

The per-module pages in the navigation are generated from that index and a shared Markdown template. Each generated
module page contains the publication table you see in the sidebar, with one row per published Maven publication and
links to the corresponding JSON/XML SBOM files, plus detached signature links when signature artifacts are present.

## Tooling

These SBOMs are standard CycloneDX documents and can be consumed directly by established tooling such as
Dependency-Track, OWASP Dependency-Check integrations that support CycloneDX, Syft/Grype workflows, and other
CycloneDX-compatible scanners and inventory systems.


## Why not GitHub Dependency Graph
GitHub’s dependency graph and its automatic generation are certainly very convenient. Unfortunately, however, both their usefulness and, even more importantly, their explanatory value are limited. The reason is that GitHub publishes not only the dependencies of the released artifacts, but all dependencies indiscriminately, regardless of whether they are test dependencies or dependencies of the toolchain, and does so without reflection or categorization.

For that reason, we decided to generate meaningful SBOMs ourselves, publish them automatically with each release, and document them here as part of the documentation.