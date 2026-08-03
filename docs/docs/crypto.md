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
    For the general data-class-first serialization workflow, see the [Serialization Tutorial](kxs.md).

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
    
    * Semantic validation of cryptographic structures (it does perform strict structural validations)
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
- `Pkcs1RsaPrivateKeyInfo`
- `Pkcs1RsaPublicKeyInfo`
- `Pkcs1RsaOtherPrimeInfo`
- `Sec1EcPrivateKeyInfo`
- `X509SignatureValue`
- `X509AlgorithmIdentifier`
- `RsaSsaPssParams`
- `X509Certificate`
- `X509TbsCertificate`
- `X509CertificateExtension`
- `Pkcs10CertificationRequest`
- `Pkcs10CertificationRequestInfo`
- `Pkcs10CsrAttribute`
- DN-related helper models such as `X500RelativeDistinguishedName` and `X500AttributeTypeAndValue`

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
    [Signum](https://a-sit-plus.github.io/signum/) is currently being ported to build on top of awesn1 and provides a full Kotlin multiplatform cryptography stack. Batteries included.

## Typical Use Cases

The `crypto` already handles the most common cryptographic data structures out of the box. It lets you:

- Parse X.509 certificates and inspect their structure
- Read or write PEM-Encoded public keys
- Handle PKCS#10 certificate signing requests
- Preserve, round-trip, or transform cryptographic ASN.1 data in Kotlin Multiplatform code
- Use these models as strongly typed payloads in ASN.1/DER serialization workflows

## PKCS#10 Attributes

`Pkcs10CertificationRequestInfo.rawAttributes` and `Pkcs10CsrAttribute.rawValue` use `LenientSet` so malformed input
can be inspected without discarding duplicate elements or wire order. Use the `attributes` and `value` properties for
validated set views. These getters throw `Asn1Exception` for malformed decoded collections; `attributes` additionally
rejects duplicate attribute OIDs.

Programmatic constructors accept Kotlin sets, but reject empty attribute values and duplicate attribute OIDs. Encoding
of programmatically created objects uses canonical DER `SET OF` ordering.
An empty `CertificationRequestInfo.attributes` set remains valid. The
`Pkcs10CsrAttribute.ExtensionRequest` helper requires at least one extension.

## Extending X.509 `OtherName`

`X509GeneralName.Other` is extensible by OID. By default, X.509 `OtherName` is (de)serialized as
`X509GeneralName.Other.SemanticValue.Generic`, preserving the OID and ASN.1 payload for a
lossless round trip. Applications can add semantic representations for known OIDs by implementing
`X509GeneralName.Other.SemanticValue` and providing the OID through `OidProvider`.

The following example implements Microsoft's `User Principal Name` form. The `0` tag annotation shown here belongs to that
specific `OtherName` payload schema.

```kotlin
--8<-- "at/asitplus/awesn1/crypto/X509OtherNameOpenPolymorphismTest.kt:crypto-x509-other-name-subtype"
```

To use the subtype with the default `DER` instance, register it during startup using the
[Default `DER` Registry](kxs.md#default-der-registry). Registration must happen before the first access to `DER`
. Keep the generic
`catchAll` in the registration if certificates containing unknown `otherName` OIDs must remain decodable.

```kotlin
--8<-- "Test.kt:crypto-x509-other-name-default-der-registration"
```

After startup registration, ordinary calls through the default `DER` instance resolve the custom semantic subtype:

```kotlin
--8<-- "at/asitplus/awesn1/crypto/X509OtherNameOpenPolymorphismTest.kt:crypto-x509-other-name-default-der-usage"
```

If global startup registration is unsuitable, configure the same `polymorphicByOid` block on a dedicated `Der`
instance and pass that instance to the relevant encoding, decoding, or certificate-extension helper calls.
