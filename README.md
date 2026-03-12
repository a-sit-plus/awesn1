<div align="center">

<img src="docs/docs/assets/awesn1.svg" width="400" alt="awesn1">

# Awesome Syntax Notation One

[![A-SIT Plus Official](https://raw.githubusercontent.com/a-sit-plus/a-sit-plus.github.io/709e802b3e00cb57916cbb254ca5e1a5756ad2a8/A-SIT%20Plus_%20official_opt.svg)](https://plus.a-sit.at/open-source.html)
[![GitHub licence](https://img.shields.io/badge/license-Apache%20License%202.0-brightgreen.svg)](http://www.apache.org/licenses/LICENSE-2.0)
[![Kotlin](https://img.shields.io/badge/kotlin-multiplatform-orange.svg?logo=kotlin)](http://kotlinlang.org)
[![Kotlin](https://img.shields.io/badge/kotlin-2.3.0-blue.svg?logo=kotlin)](http://kotlinlang.org)
[![Java](https://img.shields.io/badge/java-17-blue.svg?logo=OPENJDK)](https://www.oracle.com/java/technologies/downloads/#java17)
[![Maven Central](https://img.shields.io/maven-central/v/at.asitplus.awesn1/core)](https://mvnrepository.com/artifact/at.asitplus.awesn1/core)

**Stop writing ASN.1. Model Kotlin data classes.**

[Docs](https://a-sit-plus.github.io/awesn1/core/) • [API Docs](https://a-sit-plus.github.io/awesn1/dokka/) • [Maven Central](https://mvnrepository.com/artifact/at.asitplus.awesn1/core)

</div>

awesn1 makes ASN.1 feel less like a punishment and more like a power-up. It is a Kotlin Multiplatform toolbox for DER, rich ASN.1 domain types, low-level wire work, and first-class `kotlinx.serialization` support.

If you want to model Kotlin types and get real ASN.1 bytes out the other end, awesn1 is the fast path. If you need to drop to raw TLV trees, explicit tags, OIDs, PEM, or byte-level control, it handles that too without blinking.

## Why awesn1

- Turn `@Serializable` Kotlin classes into DER with the `kxs` module.
- Build and inspect raw ASN.1 trees with a typed low-level model and builder DSL.
- Work with real ASN.1 domain types like `ObjectIdentifier`, `Asn1Integer`, `Asn1Real`, `Asn1Time`, and `Asn1String`.
- Add `kotlinx-io` integration when your code lives on `Source` and `Sink`.
- Load known OIDs through the optional `oids` module for readable diagnostics and developer tooling.
- Full CycloneDX SBOMs on Maven Central alongside published artifacts for all targets.

## Pick your module

| Module   | Use it when you need...                                                                             |
|----------|-----------------------------------------------------------------------------------------------------|
| `core`   | the ASN.1 element model, DER parsing/encoding helpers, PEM support, rich types, and the builder DSL |
| `kxs`    | `kotlinx.serialization` integration so Kotlin models encode and decode as ASN.1 DER                 |
| `io`     | low-level ASN.1 parsing and encoding on `kotlinx.io.Source` and `kotlinx.io.Sink`                   |
| `crypto` | cryptographic data structures, such as certificates, SPKIs, CSRs, etc.                              |
| `kxs-io` | DER `kotlinx.serialization` flows directly on `Source`/`Sink`                                       |
| `oids`   | a bundled registry of known object identifiers and human-readable descriptions                      |

## Get started

```kotlin
implementation("at.asitplus.awesn1:core:$version")
implementation("at.asitplus.awesn1:kxs:$version")
```

Start with `core` if you want the low-level ASN.1 toolbox. Add `kxs` when you want the headline act: _Kotlin models in, DER out_.

Model the data. Encode it. Decode it. No handwritten ASN.1 schema gymnastics required.

```kotlin
import at.asitplus.awesn1.serialization.DER
import kotlinx.serialization.Serializable

@Serializable
data class Person(
    val name: String,
    val age: Int,
)

val value = Person(name = "A", age = 5)
val der = DER.encodeToByteArray(value)
check(der.toHexString() == "30060c0141020105")

val decoded = DER.decodeFromByteArray<Person>(der)
check(decoded == value)
```

That is a DER `SEQUENCE` containing a UTF-8 string and an integer. awesn1 handles the ASN.1 wire shape so you can stay focused on the Kotlin model.

## What Next

Awesome Syntax Notation One comes with extensive documentation that lets you interactively explore
the ASN.1 structures used in the examples:

- [Docs Overview](https://a-sit-plus.github.io/awesn1/core/)
- [Serialization Guide](https://a-sit-plus.github.io/awesn1/kxs/)
- [Low-Level ASN.1 API](https://a-sit-plus.github.io/awesn1/lowlevel/)
- [API Docs](https://a-sit-plus.github.io/awesn1/dokka/)
- [SBOM Overview](https://a-sit-plus.github.io/awesn1/sbom/)

## Contributing

External contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for workflow details and the A-SIT Plus Contributor License Agreement requirements.

---

<p align="center">
The Apache License does not apply to the logos, including the A-SIT logo, or the project and module names. These remain the property of A-SIT/A-SIT Plus GmbH and may not be used in derivative works without explicit permission.
</p>
