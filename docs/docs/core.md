---
hide:
  - navigation
---


<div class="core-badges-centered">
  <img src="../assets/awesn1.svg" width="320" alt="awesn1">
  <p>
    <a href="https://plus.a-sit.at/open-source.html"><img alt="A-SIT Plus Official" src="https://raw.githubusercontent.com/a-sit-plus/a-sit-plus.github.io/709e802b3e00cb57916cbb254ca5e1a5756ad2a8/A-SIT%20Plus_%20official_opt.svg"></a>
    <a href="http://www.apache.org/licenses/LICENSE-2.0"><img alt="GitHub licence" src="https://img.shields.io/badge/license-Apache%20License%202.0-brightgreen.svg"></a>
    <a href="http://kotlinlang.org"><img alt="Kotlin Multiplatform" src="https://img.shields.io/badge/kotlin-multiplatform-orange.svg?logo=kotlin"></a>
    <a href="http://kotlinlang.org"><img alt="Kotlin 2.3.0" src="https://img.shields.io/badge/kotlin-2.3.0-blue.svg?logo=kotlin"></a>
    <a href="https://www.oracle.com/java/technologies/downloads/#java17"><img alt="Java 17" src="https://img.shields.io/badge/java-17-blue.svg?logo=OPENJDK"></a>
    <a href="https://mvnrepository.com/artifact/at.asitplus.awesn1/core"><img alt="Maven Central" src="https://img.shields.io/maven-central/v/at.asitplus.awesn1/core"></a>
  </p>
</div>

# Overview

Awesome Syntax Notation One <ruby>
(awesn1)
<rt>/ɑː es en wʌn/</rt>
</ruby> makes ASN.1 a joy to work with; probably for the first time ever.
It provides the most sophisticated [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html) ASN.1 toolbox in the known
universe. It gives you:

- First-class kotlinx.serialization support through a dedicated `kxs` module (see [Serialization](kxs.md)).  
  Simply model Kotlin classes and never care for ASN.1 details again. No sleight of hand, no cheap tricks!
- ASN.1 element types (`Asn1Element`, `Asn1Primitive`, `Asn1Structure`)
- DER parsing/encoding helpers
- A builder DSL for manual ASN.1 trees (`Asn1.Sequence`, `Asn1.Set`, `Asn1.ExplicitlyTagged`, ...)
- Rich ASN.1 domain types (`ObjectIdentifier`, `Asn1Integer`, `Asn1Real`, `Asn1Time`, `Asn1String`, `BitSet`)
- Addons for integrating with [kotlinx-io](https://github.com/Kotlin/kotlinx-io) (see [io addons](addons.md#kxs-io))
- Optional known OID registry (see [OID addons](addons.md#oids))

## Maven Coordinates

```kotlin
implementation("at.asitplus.awesn1:core:$version")
```

## What About Certificates, Public Keys, and PKI Types?

Those are intentionally not part of `core`.

`core` contains generic ASN.1 infrastructure and rich built-in ASN.1 data types.
Cryptographic structures such as X.509 certificates, `SubjectPublicKeyInfo`, `PrivateKeyInfo`, PKCS#10 requests,
and related PKI data classes live in the dedicated [crypto](crypto.md) module instead.

That split keeps `core` small and broadly reusable, while `crypto` builds on top of it with
cryptography-specific data models.

## Supply Chain Metadata

CycloneDX SBOMs for awesn1 are published with each Maven publication on Maven Central and exported on this
documentation site. See [SBOM](sbom.md) for publication-specific JSON/XML downloads and the machine-readable index.

## Package Map

- `at.asitplus.awesn1`:
  Element model, rich ASN.1 types, tagging, parsing helpers.
- `at.asitplus.awesn1.encoding`:
  Builder DSL plus low-level encode/decode helpers.
- `at.asitplus.awesn1.serialization`:
  `kotlinx.serialization` format (provided by the `kxs` module).

## Serialization Example: RFC CHOICE with Sealed Polymorphism

!!! tip "`kotlinx.serialization` integration "
    Integration with `kotlinx.serialization` requires the `kxs` module. If you require kotlinx.serialization support 
    add the following dependency:
    
    ```kotlin
    implementation("at.asitplus.awesn1:kxs:$version")
    ```

    The `kxs` module provides the DER format implementation (`DER.encodeToByteArray`, `DER.decodeFromByteArray`, ...).
    Core ASN.1 types such as `Asn1Integer`, `Asn1Real`, and `ObjectIdentifier` are serializable in a way that they can also be used
    with non-DER formats.

This example models a subset of `GeneralName ::= CHOICE` from RFC 5280 (`dNSName [2] IA5String`,
`uniformResourceIdentifier [6] IA5String`), encodes two alternatives, round-trips decoding, and asserts exact DER hex
bytes.

Reference: [RFC 5280, GeneralName](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6).

```kotlin
--8<-- "at/asitplus/awesn1/docs/CoreDocumentationHooksTest.kt:core-hook-serialization-choice-rfc"
```

1. {{ asn1js_iframe('core-hook-serialization-choice-dns') -}}
   Explore on <a href="{{ asn1js_url('core-hook-serialization-choice-dns') }}" target="_blank" rel="noopener">
   asn1js.eu</a>
2. {{ asn1js_iframe('core-hook-serialization-choice-uri') -}}
   Explore on <a href="{{ asn1js_url('core-hook-serialization-choice-uri') }}" target="_blank" rel="noopener">
   asn1js.eu</a>

For a complete envelope-style serialization walkthrough (raw payload preservation, implicit tagging,
signature-verification use-case), see the [Serialization Tutorial](kxs.md#signed-data-with-raw-payload-preservation).

## ASN.1 Builder DSL Showcase

awesn1 comes with a type-safe ASN.1 Builder DSL:

```kotlin
--8<-- "at/asitplus/awesn1/docs/CoreDocumentationHooksTest.kt:core-hook-builder"
```

1. {{ asn1js_iframe('core-hook-builder') -}}
   Explore on <a href="{{ asn1js_url('core-hook-builder') }}" target="_blank" rel="noopener">asn1js.eu</a>

## Example: Define Your Own Semantic Type

Low-Level ASN.1 modelling and processing is also possible.
To define custom types, implement `Asn1Encodable` and provide a companion `Asn1Decodable` when you want a semantic model
on top of raw TLV.
If you want it to be serializable in DER, make the companion also implement `Asn1Serializable` and reference it in the
`@Serializable` annotation on your type.
(Note that this works only for ASN.1 serialization, not in a generic fashion.)

```kotlin
--8<-- "at/asitplus/awesn1/docs/CoreDocumentationHooksTest.kt:core-hook-custom-type"
```

```kotlin
--8<-- "at/asitplus/awesn1/docs/CoreDocumentationHooksTest.kt:core-hook-custom-roundtrip"
```

1. {{ asn1js_iframe('core-hook-custom-roundtrip') -}}
   Explore on <a href="{{ asn1js_url('core-hook-custom-roundtrip') }}" target="_blank" rel="noopener">asn1js.eu</a>

## PEM Armor

`core` includes generic PEM support:

- `PemBlock` / `PemHeader` data structures
- `decodeFromPem` / `encodeToPem` for single blocks
- `decodeAllFromPem` / `encodeAllToPem` for PEM documents with multiple blocks
- independent `PemEncodable` / `PemDecodable` contracts
- `Asn1PemEncodable` / `Asn1PemDecodable` bridge contracts for ASN.1 DER payloads

### Generic PEM (opaque payload bytes)

Use this when you want to parse or emit PEM without caring what the payload is:

```kotlin
--8<-- "at/asitplus/awesn1/docs/CoreDocumentationHooksTest.kt:core-hook-pem-generic"
```

### ASN.1 Payloads Inside PEM

If your PEM payload is ASN.1 DER, implement both ASN.1 and PEM bridge contracts:

```kotlin
--8<-- "at/asitplus/awesn1/docs/CoreDocumentationHooksTest.kt:core-hook-pem-asn1"
```


## Background

awesn1 was originally called [Indispensable ASN.1](https://a-sit-plus.github.io/signum/indispensable-asn1/) and was one
of [Signum](https://a-sit-plus.github.io/signum/)'s pillars: a comprehensive Kotlin Multiplatform ASN.1 implementation.
It'd design was shaped by production use and informed by opinionated design choices based real-world experience.

That original design came with trade-offs. To support Swift usage, it depended
on [KmmResult](https://a-sit-plus.github.io/KmmResult/). At the same time, it focused narrowly on ASN.1’s format
details, and its API was heavily tailored to Signum’s use cases.

With feedback from [Oleg Yukhnevich](https://github.com/whyoleg), first-class kotlinx.serialization support
was prioritised, and awesn1 was separated into an independent library.
Third-party dependencies were removed, the API was simplified, and the core was streamlined. Integration
with [kotlinx-io](https://github.com/Kotlin/kotlinx-io) is now optional.
In the end, the already solid ASN.1 handling was barely touched, only delicately polished.

--- 

<blockquote>
Whenever ASN.1 makes me sad, I stop being sad and be awesome instead. True story.
</blockquote>
&mdash;&hairsp;awesn1 users
