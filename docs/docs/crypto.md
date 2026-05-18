---
hide:
  - navigation
---

# Cryptographic Datastructures

The `crypto` module provides ASN.1-backed cryptographic and PKI model types built on top of awesn1 `core`.
If you are looking for certificates, public keys, private keys, PKCS#10 requests, or common algorithm identifiers,
this is the module you want.

!!! info "`kxs`-powered starting with 0.3.0"
    The `crypto` module depends on both `core` and `kxs`.
    DER handling in `crypto` now goes through awesn1's `kotlinx.serialization` integration from `kxs`,
    rather than manual DER encode/decode implementations inside `crypto`.

## Why This Is Not in `core`

`core` is intentionally limited to generic ASN.1 infrastructure:

- ASN.1 elements and rich scalar/domain types
- DER parsing and encoding
- tagging
- PEM support
- the generic ASN.1 serialization contract

Cryptographic structures sit one level above that.
They are still ASN.1, but they are not universally useful building blocks in the same way as
`Asn1Integer`, `ObjectIdentifier`, or `Asn1Time`.
Keeping them in a separate module keeps `core` small, generic, and reusable.

!!! warning "This is not a full-fledged cryptography stack"
    The `crypto` module is not trying to provide:
    
    * Semantic validation of cryptographic structures (it does perform stric structural validations)
    * Certificate path validation
    * Signature verification policy
    * …
    
    If you need any of those, check out [Signum](https://a-sit-plus.github.io/signum/), which is currently being ported over to work on top of awesn1. 

## Maven Coordinates

```kotlin
implementation("at.asitplus.awesn1:crypto:$version")
```

## Scope

At a high level, the module focuses on structural cryptographic and PKI data models rather than validation,
policy enforcement, or cryptographic operations.

### Cryptographic Data Structures

The module currently includes models such as:

- `SubjectPublicKeyInfo`
- `Pkcs8PrivateKeyInfo`
- `EncryptedPrivateKeyInfo`
- `RsaPublicKeyInfo`
- `Pkcs1RsaPrivateKeyInfo`
- `Pkcs1RsaOtherPrimeInfo`
- `Sec1EcPrivateKeyInfo`
- `SignatureValue`
- `X509AlgorithmIdentifier`
- `RsaSsaPssParams`
- `X509Certificate`
- `X509TbsCertificate`
- `X509CertificateExtension`
- `Pkcs10CertificationRequest`
- `Pkcs10CertificationRequestInfo`
- DN-related helper models such as `X500RelativeDistinguishedName`, `X500AttributeTypeAndValue`, and `Attribute`

These are structural models.
They parse and encode ASN.1 DER correctly, but they do not aim to be a full certificate validation stack,
trust engine, or cryptographic provider.

### Not in Scope

The `crypto` module is not trying to provide:

- certificate path validation
- hostname verification
- signature verification policy
- trust store management
- high-level JOSE/CMS/COSE stacks
- key generation or cryptographic primitives

Those concerns are deliberately separate from the ASN.1 structural layer.

!!! tip "Looking for a KMP crypto provider?"
[Signum](https://a-sit-plus.github.io/signum/) builds on awesn1 and provides a full Kotlin multiplatform cryptography stack. Batteries included.

## Typical Use Cases

The `crypto` already handles the most common cryptographic data structures out of the box. It lets you:

- Parse X.509 certificates and inspect their structure
- Read or write PEM-Encoded public keys
- Handle PKCS#10 certificate signing requests
- Preserve, round-trip, or transform cryptographic ASN.1 data in Kotlin Multiplatform code
- Use these models as strongly typed payloads in ASN.1/DER serialization workflows

## Relationship to Serialization

The crypto model classes are ASN.1-serializable and their DER handling is implemented through awesn1's
`kotlinx.serialization`-based `DER` format from the `kxs` module.

That means you can use them either:

- through low-level ASN.1 APIs from `core`
- or through `DER.encodeToByteArray(...)` / `DER.decodeFromByteArray(...)` from `kxs`

For the general data-class-first serialization workflow, see the [Serialization Tutorial](kxs.md).
