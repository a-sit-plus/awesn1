---
hide:
  - navigation
---

# Integration with `kotlinx.serialization`

This page shows how to use awesn1 with `kotlinx.serialization`. DER format support is provided by the discrete
`kxs` module.

Core awesn1 types are serializable. When encoded with awesn1's `DER` format, they use proper ASN.1 TLV/DER encoding.
When encoded with non-DER formats, fallback representations are used.

## Default `DER` Registry

The default `DER` instance is immutable once it has been initialized, but its serializers module can be extended
before that first use through an opt-in registry.

This exists for a practical reason: higher-level models often keep raw ASN.1 backing fields and derive transient
semantic fields from those raw elements. If those transient fields need to decode through the default `DER` instance,
the relevant contextual or open-polymorphic serializers must already be present without forcing every caller to
manually rebuild the format.

The contract is intentionally strict:

- default-DER contributors must register before the first access to `DER`
- after the default `DER` instance has been initialized, further registrations throw
- `Der` itself stays immutable; only the pre-initialization contributor list is extensible

Typical reasons to add contributors are domain-specific open polymorphism and raw-backed semantic wrappers.
One concrete example is introducing new ASN.1 signature formats beyond awesn1's built-in `SignatureValue`
subtypes: those additional serializers must be registered before the default `DER` instance is first used.

!!! warning "`SignatureValue` Registration"
    awesn1 keeps the `DER` registry generic. Built-in `SignatureValue` support must be manually installed when using the `crypto` module by calling
    [`registerSignatureValueForDefaultDer()`](https://a-sit-plus.github.io/awesn1/crypto/) **before any call to `DER`**!  
    Signum's own mandatory serialization hook calls it by default:
    [`registerSignumDefaultDerSerializers()`](https://a-sit-plus.github.io/signum/indispensable/#registry-initialization-and-extension-registration).

Sketch:

```kotlin
@Serializable(with = Ed448SignatureValue.Companion::class)
class Ed448SignatureValue(
    val octets: Asn1OctetString,
) : SignatureValue, Asn1Encodable<Asn1Primitive> {
    override fun encodeToTlv(): Asn1Primitive = octets.encodeToTlv()

    companion object : Asn1Serializable<Asn1Primitive, Ed448SignatureValue> {
        override val leadingTags = setOf(Asn1Element.Tag.OCTET_STRING)

        override fun doDecode(src: Asn1Primitive) =
            Ed448SignatureValue(src.asAsn1OctetString())
    }
}

@OptIn(ExperimentalSerializationApi::class)
fun registerEd448ForDefaultDer() {
    registerSignatureValueForDefaultDer()
    DefaultDerSerializersModuleRegistry.register(
        SerializersModule {
            polymorphicByTag(
                SignatureValue::class,
                serialName = DEFAULT_DER_SIGNATURE_VALUE_SERIAL_NAME,
            ) {
                subtype<Ed448SignatureValue>(Asn1Element.Tag.OCTET_STRING)
            }
        }
    )
}
```

The important part is that the registration happens before the first access to `DER`. For a new signature family, first
install the built-in `SignatureValue` hook from awesn1 crypto, then register your additional subtype mapping in the same
pre-initialization phase.

This design avoids a mutable global codec while still allowing library integrations to make raw-backed transient
materialization work out of the box.

??? info "Non-DER Fallback Representations"

    - `ObjectIdentifier` serializes as dotted-decimal text (`1.2.840...`)
    - `Asn1Integer` serializes as decimal string (due to being arbitrary precision)
    - `Asn1Real` (`Zero`, `PositiveInfinity`, `NegativeInfinity`, `Finite`) serializes as string (due to being arbitrary precision)
    - `Asn1String` and concrete subtypes (`UTF8`, `Universal`, `Visible`, `IA5`, `Teletex`, `BMP`, `General`, `Graphic`, `Unrestricted`, `Videotex`, `Printable`, `Numeric`) serialize as plain string
    - `Asn1Time` serializes as plain `Instant` string form
    - `Asn1BitString` serializes as a string surrogate containing padding and Base64 payload
    - `BitSet` serializes as a bit-string view (`101001...`)
    - `Asn1Element`, `Asn1Structure`, `Asn1ExplicitlyTagged`, `Asn1CustomStructure`, `Asn1EncapsulatingOctetString`, `Asn1PrimitiveOctetString`, `Asn1Set`, `Asn1SetOf`, `Asn1Primitive`, and `Asn1OctetString` serialize as Base64-encoded DER bytes

    **Warning**: Non-DER fallback serialization is intentionally lossy for `Asn1String` and `Asn1Time` for cross-format simplicity.
    `Asn1String` deserializes to `UTF8` (original ASN.1 string subtype is not preserved), and `Asn1Time` deserializes
    from `Instant` only (original UTC TIME vs GENERALIZED TIME choice is not preserved where ranges overlap).


## Maven Coordinates

```kotlin
implementation("at.asitplus.awesn1:kxs:$version")
```

## Baseline Mapping

awesn1's `DER` codec makes `@Serializable` class work with ASN.1 automatically.
Any serializable class maps to ASN.1 `SEQUENCE` by default, as shown below.

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-baseline-definitions"
```

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-baseline-roundtrip"
```

1. {{ asn1js_iframe('kxs-baseline') -}}
   Explore on <a href="{{ asn1js_url('kxs-baseline') }}" target="_blank" rel="noopener">asn1js.eu</a>

## Overriding Tags with `@Asn1Tag`

Use `@Asn1Tag` for implicit tag overrides when your wire format requires a specific context-specific tag number.
This is common in profiles that refine generic ASN.1 structures into tightly specified field layouts.
You will see this pattern throughout [X.509 (RFC 5280)](https://www.rfc-editor.org/rfc/rfc5280), especially in
extension and name-related structures.

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-tag-override-definitions"
```

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-tag-override-roundtrip"
```

1. {{ asn1js_iframe('kxs-tag-override') -}}
   Explore on <a href="{{ asn1js_url('kxs-tag-override') }}" target="_blank" rel="noopener">asn1js.eu</a>

## Modelling EXPLICIT Wrappers

Use `ExplicitlyTagged<T>` with a constructed context-specific tag when the schema requires an extra wrapper layer
around the actual value.
This shows up in protocol designs that intentionally preserve type boundaries for forward compatibility or profile
conformance.
For examples of explicit tagging in broadly deployed PKI syntax, see
[CMS (RFC 5652)](https://www.rfc-editor.org/rfc/rfc5652).

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-explicit-wrapper-definitions"
```

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-explicit-wrapper-roundtrip"
```

1. {{ asn1js_iframe('kxs-explicit-wrapper') -}}
   Explore on <a href="{{ asn1js_url('kxs-explicit-wrapper') }}" target="_blank" rel="noopener">asn1js.eu</a>

## Modelling CHOICE with Sealed Types

Sealed polymorphism maps naturally to ASN.1 `CHOICE`, where one wire value can represent one of several
subtypes.
This is a direct fit for data families such as identity names, algorithm parameters, and extension payload variants.
A common real-world example is `GeneralName` in [X.509 (RFC 5280)](https://www.rfc-editor.org/rfc/rfc5280).

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-choice-definitions"
```

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-choice-roundtrip"
```

1. {{ asn1js_iframe('kxs-choice-int') -}}
   Explore on <a href="{{ asn1js_url('kxs-choice-int') }}" target="_blank" rel="noopener">asn1js.eu</a>
2. {{ asn1js_iframe('kxs-choice-bool') -}}
   Explore on <a href="{{ asn1js_url('kxs-choice-bool') }}" target="_blank" rel="noopener">asn1js.eu</a>

### Primitive CHOICE Alternatives

When the CHOICE alternatives are just primitive wrappers, sealed inline value classes work as well. This keeps the
Kotlin model compact while still allowing per-arm ASN.1 annotations where needed.

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-choice-primitive-definitions"
```

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-choice-primitive-roundtrip"
```

1. {{ asn1js_iframe('kxs-choice-primitive-int') -}}
   Explore on <a href="{{ asn1js_url('kxs-choice-primitive-int') }}" target="_blank" rel="noopener">asn1js.eu</a>
2. {{ asn1js_iframe('kxs-choice-primitive-bool') -}}
   Explore on <a href="{{ asn1js_url('kxs-choice-primitive-bool') }}" target="_blank" rel="noopener">asn1js.eu</a>
3. {{ asn1js_iframe('kxs-choice-primitive-text') -}}
   Explore on <a href="{{ asn1js_url('kxs-choice-primitive-text') }}" target="_blank" rel="noopener">asn1js.eu</a>

## Open Polymorphism by Leading Tag

When you have open polymorphism and subtypes are distinguishable by ASN.1 tag alone, dispatch by leading tag is the
simplest robust option.
This keeps type resolution local to the encoded element and avoids schema-specific side channels.
This style appears in tagged alternatives in [X.509 (RFC 5280)](https://www.rfc-editor.org/rfc/rfc5280) and related
certificate ecosystems.

First, a non-value-class example modeled after RFC-style `GeneralName` alternatives (`dNSName` and `uniformResourceIdentifier`):

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-open-poly-tag-rfc-definitions"
```

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-open-poly-tag-rfc-roundtrip"
```

1. {{ asn1js_iframe('kxs-open-poly-tag-rfc-dns') -}}
   Explore on <a href="{{ asn1js_url('kxs-open-poly-tag-rfc-dns') }}" target="_blank" rel="noopener">asn1js.eu</a>
2. {{ asn1js_iframe('kxs-open-poly-tag-rfc-uri') -}}
   Explore on <a href="{{ asn1js_url('kxs-open-poly-tag-rfc-uri') }}" target="_blank" rel="noopener">asn1js.eu</a>

The non-value-class approach is usually preferable when each variant carries additional semantics beyond a single primitive
field, for example, validation hooks, helper methods, or room for future schema growth.
It also mirrors how many RFC text definitions are documented conceptually: named alternatives with explicit meaning,
even if their payload is currently simple.

Value classes are still useful when a variant is intentionally a very thin wrapper around one scalar and you want the
most compact model in Kotlin source.
Both approaches use the exact same polymorphic-by-tag dispatch mechanism in awesn1; the difference is mostly about
modeling style and maintainability constraints in your domain code.

Second, the same mechanism with value classes:

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-open-poly-tag-valueclass-definitions"
```

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-open-poly-tag-valueclass-roundtrip"
```

1. {{ asn1js_iframe('kxs-open-poly-tag-valueclass-int') -}}
   Explore on <a href="{{ asn1js_url('kxs-open-poly-tag-valueclass-int') }}" target="_blank" rel="noopener">asn1js.eu</a>
2. {{ asn1js_iframe('kxs-open-poly-tag-valueclass-bool') -}}
   Explore on <a href="{{ asn1js_url('kxs-open-poly-tag-valueclass-bool') }}" target="_blank" rel="noopener">asn1js.eu</a>

## Open Polymorphism by OID

For OID-based domains, dispatch by object identifier instead of by tag when multiple subtypes can share the same
outer ASN.1 shape.
This is the standard strategy for algorithm identifiers, extension payloads, and typed attribute value containers.
Real-world references include [PKCS #10 (RFC 2986)](https://www.rfc-editor.org/rfc/rfc2986),
[CMS (RFC 5652)](https://www.rfc-editor.org/rfc/rfc5652), and [X.509 (RFC 5280)](https://www.rfc-editor.org/rfc/rfc5280).

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-open-poly-oid-definitions"
```

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-open-poly-oid-roundtrip"
```

1. {{ asn1js_iframe('kxs-open-poly-oid') -}}
   Explore on <a href="{{ asn1js_url('kxs-open-poly-oid') }}" target="_blank" rel="noopener">asn1js.eu</a>

## Collections: `Map` and `Set`

Default mappings for `Map` and `Set` are supported, so idiomatic Kotlin collection models can be encoded without
custom serializers in many cases.
This is useful for attribute bags, extension dictionaries, and grouped values that naturally map to ASN.1 collection
constructs.
In PKI and signed-message standards, `SET` and sequence-of-entry patterns are common; see
[X.509 (RFC 5280)](https://www.rfc-editor.org/rfc/rfc5280) and [CMS (RFC 5652)](https://www.rfc-editor.org/rfc/rfc5652).

- Kotlin `Set<T>` maps to ASN.1 `SET` semantics.
- Kotlin `Map<K, V>` is encoded as a structured collection of key/value entries.

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-map-set-definitions"
```

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-map-set-roundtrip"
```

1. {{ asn1js_iframe('kxs-map-set') -}}
   Explore on <a href="{{ asn1js_url('kxs-map-set') }}" target="_blank" rel="noopener">asn1js.eu</a>

## Retaining and Re-Emitting Raw ASN.1 Data

This topic is about interoperability under non-ideal conditions: preserving exact input bytes when you cannot assume
fully canonical upstream encoders.
It matters in cryptographic workflows where signature input fidelity is as important as semantic correctness.
You will encounter this in certificate validation stacks, trust service integrations, and large-scale protocol gateways.

### Raw `Asn1Set` for Non-Canonical Input

Some systems produce ASN.1 `SET` elements with wrong DER member ordering. Decoding into a plain Kotlin `Set` loses the
original wire order immediately, which is a problem if the raw data is needed, for example, for signature verification.
If you must keep exact bytes for re-emission, model the property as raw `Asn1Set` and materialize your domain view via
a `@Transient` Kotlin `Set`.
This pattern is especially relevant for signature verification and audit trails where re-encoding must not normalize
away sender-specific quirks.

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-raw-set-preservation-definitions"
```

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-raw-set-preservation-roundtrip"
```

1. {{ asn1js_iframe('kxs-raw-set-preservation-canonical') -}}
   Canonical encoding from rich model (`Asn1Set` sorts by DER rules). Explore on <a href="{{ asn1js_url('kxs-raw-set-preservation-canonical') }}" target="_blank" rel="noopener">asn1js.eu</a>
2. {{ asn1js_iframe('kxs-raw-set-preservation-noncanonical') -}}
   Re-encoding decoded third-party non-canonical input preserves original wrong order. Explore on <a href="{{ asn1js_url('kxs-raw-set-preservation-noncanonical') }}" target="_blank" rel="noopener">asn1js.eu</a>

### Signed Data with Raw Payload Preservation

This example models a `SignedBox` envelope for signed data.
The main requirement is signature verification: we need the exact original signature input as raw ASN.1, so we can
always recover unmodified DER bytes.
This mirrors practical requirements in detached signatures, timestamp containers, and certificate-based token systems.
For standard background, see [CMS (RFC 5652)](https://www.rfc-editor.org/rfc/rfc5652).

Real-world ASN.1 codecs (or rather: the business logic built on top) typically produce structurally valid data but are sometimes not perfectly spec-conformant at the encoding level.
For example, production implementations exist that misencode `TRUE` or show other low-level flaws.
See:
[encoding flaws documented by Warden Supreme](https://a-sit-plus.github.io/warden-supreme/technical/quirks/#encoding-flaws) for real-world examples at scale.

For this example, we assume `ExamplePayload` is a normal domain model defined elsewhere and reused in multiple contexts.
In `SignedBox`, this payload must be implicitly tagged according to spec, but we also want to preserve it as raw
`Asn1Element`.
Directly combining implicit tagging and raw `Asn1Element` with kotlinx.serialization is intentionally prohibited
because it creates ambiguous decoding semantics.

The pattern in this sample uses a value class to still get the job done:

- `RawTaggedPayload` stores the raw implicitly tagged element for byte-exact re-use.
- `ImplicitlyTaggedPayload` (value class with `@Asn1Tag`) provides the schema-level tagging contract.
- a `@Transient` parsed value is materialized at instantiation time, so structurally invalid raw payloads are rejected
  immediately.
- both `payload` and `signature` in `SignedBox` are implicitly tagged members.
- strict rich decoding rejects known non-canonical encodings (for example `BOOLEAN TRUE = 0x01`) while still exposing
  the canonical raw payload element when decoding succeeds.

This pattern is the complex extension of the implicit-tagging workaround shown in `ElementTaggingTest` (`ValueClassImplicitlyTaggedElement`).

```kotlin
--8<-- "at/asitplus/awesn1/docs/CoreDocumentationHooksTest.kt:core-hook-serialization-signedbox-definitions"
```

```kotlin
--8<-- "at/asitplus/awesn1/docs/CoreDocumentationHooksTest.kt:core-hook-serialization-signedbox-roundtrip"
```

1. As can be seen, implicit tagging is applied.
2. {{ asn1js_iframe('core-hook-serialization-signedbox-canonical') -}}
   Explore on <a href="{{ asn1js_url('core-hook-serialization-signedbox-canonical') }}" target="_blank" rel="noopener">
   asn1js.eu</a>
3. {{ asn1js_iframe('core-hook-serialization-signedbox-noncanonical') -}}
   Explore on <a href="{{ asn1js_url('core-hook-serialization-signedbox-noncanonical') }}" target="_blank" rel="noopener">
   asn1js.eu</a>



## Format Options

DER format behaviour can be tuned with the DER builder:

- `explicitNulls = true`: encode nullable `null` as ASN.1 `NULL`
- `encodeDefaults = false`: omit default-valued properties

These switches are important when you need to align with profile-specific encoding expectations or with legacy systems
that depend on a specific wire form.
For strict canonicality expectations in certificate ecosystems, see
[X.509 (RFC 5280)](https://www.rfc-editor.org/rfc/rfc5280).

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-format-options-definitions"
```

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-format-options-explicit-nulls-roundtrip"
```

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-format-options-encode-defaults-roundtrip"
```

1. {{ asn1js_iframe('kxs-format-options-explicit-nulls') -}}
   Explore on <a href="{{ asn1js_url('kxs-format-options-explicit-nulls') }}" target="_blank" rel="noopener">asn1js.eu</a>
2. {{ asn1js_iframe('kxs-format-options-encode-defaults') -}}
   Explore on <a href="{{ asn1js_url('kxs-format-options-encode-defaults') }}" target="_blank" rel="noopener">asn1js.eu</a>

## `Asn1Serializer` with Low-Level Types

This section explains when low-level ASN.1 model types are enough on their own and when they need an explicit bridge
into the `kotlinx.serialization` world.
The distinction matters in mixed codebases where some types are protocol-native and others are DTOs used by app-layer
serialization pipelines.

### Top-Level Low-Level Type Without `Asn1Serializer`

At top level, a type that implements `Asn1Encodable` and provides a matching `Asn1Decodable` companion can be encoded
and decoded directly through low-level APIs.
No kotlinx serializer bridge is needed yet, because this path does not rely on descriptor-driven property decoding.
First the type and companion are defined, then the roundtrip shows the direct low-level call path.

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-asn1serializer-top-level-encodable-definitions"
```

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-asn1serializer-top-level-encodable-roundtrip"
```

1. {{ asn1js_iframe('kxs-asn1serializer-top-level-encodable') -}}
   Explore on <a href="{{ asn1js_url('kxs-asn1serializer-top-level-encodable') }}" target="_blank" rel="noopener">asn1js.eu</a>

### Same Type as a Property Failing Without a Bridge

Now the same type is embedded as a property of a `@Serializable` carrier.
At this point, awesn1 needs serializer metadata for property-level decoding decisions, and the low-level companion alone
is not enough to satisfy that contract.
The first snippet defines the carrier, and the second snippet demonstrates the failure path.

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-asn1serializer-property-without-bridge-definitions"
```

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-asn1serializer-property-without-bridge-roundtrip"
```

### Lean `Asn1Serializer` Bridge

`Asn1Serializer` is an abstract helper that supplies the property-level metadata awesn1 needs and forwards decode logic
to an existing `Asn1Decodable` companion, so there is no duplication of parsing logic.
This keeps composition explicit: low-level encode/decode behaviour stays in the model type, while the bridge only adapts
it to kotlinx descriptor-based workflows.
The first snippet shows the lean bridge declaration plus annotated carrier; the second snippet shows successful
roundtrip again.

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-asn1serializer-property-with-bridge-definitions"
```

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-asn1serializer-property-with-bridge-roundtrip"
```

1. {{ asn1js_iframe('kxs-asn1serializer-property-with-bridge') -}}
   Explore on <a href="{{ asn1js_url('kxs-asn1serializer-property-with-bridge') }}" target="_blank" rel="noopener">asn1js.eu</a>


## Deep Dive: Disambiguation

Disambiguation is the core safety mechanism that keeps decoding deterministic and secure.
Many ASN.1 interoperability issues in production systems are not parse failures but ambiguous layouts that different
implementations resolve differently.
The following steps show how ambiguity appears and how to remove it explicitly.

### Baseline: Three Non-Nullable Strings

This layout is deterministic: every field is always present.
This is the safe baseline shape you find in tightly constrained profile fields where omissions are not allowed.

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-leading-tags-non-null-definitions"
```

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-leading-tags-non-null-roundtrip"
```

1. {{ asn1js_iframe('kxs-leading-tags-non-null') -}}
   Explore on <a href="{{ asn1js_url('kxs-leading-tags-non-null') }}" target="_blank" rel="noopener">asn1js.eu</a>

### Nullable Strings with `explicitNulls = true`

Encoding `null` as ASN.1 `NULL` keeps field positions observable.
That makes omission-vs-presence semantics explicit and avoids positional ambiguity when adjacent fields share tags.

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-leading-tags-explicit-nulls-definitions"
```

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-leading-tags-explicit-nulls-roundtrip"
```

1. {{ asn1js_iframe('kxs-leading-tags-explicit-nulls') -}}
   Explore on <a href="{{ asn1js_url('kxs-leading-tags-explicit-nulls') }}" target="_blank" rel="noopener">asn1js.eu</a>

### Nullable Strings with Omitted Nulls (`explicitNulls = false`)

Now `null` fields disappear from the wire. With same-shaped neighbors (`String`, `String`, `String`), omitted middle fields
become undecidable, so serialization is rejected.
Fail-fast behavior here prevents latent interoperability and security bugs in downstream decoders.

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-leading-tags-ambiguous-null-omission-roundtrip"
```

Ambiguity is detected early and rejected at encode-time.

###  Disambiguate with Implicit Tags

Assign distinct context-specific implicit tags (common in X.509). Now each field has a distinct leading tag, so omission is
safe again.
This is a primary real-world technique for making optional fields unambiguous in certificate and extension schemas.

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-leading-tags-implicit-tagging-definitions"
```

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-leading-tags-implicit-tagging-roundtrip"
```

1. {{ asn1js_iframe('kxs-leading-tags-implicit-tagging') -}}
   Explore on <a href="{{ asn1js_url('kxs-leading-tags-implicit-tagging') }}" target="_blank" rel="noopener">asn1js.eu</a>

`EXPLICIT` tagging is another valid disambiguation strategy when schema/tooling requirements prefer wrapper elements.

### Custom Serializers Re-Introducing Ambiguity

If two nullable custom-serialized types both resolve to `SEQUENCE` and no field tags are present, nullable omission can be
ambiguous again and is rejected on encode.
This is a common pitfall when composing reusable serializers that were written independently of each other.

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-leading-tags-custom-ambiguous-definitions"
```

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-leading-tags-custom-ambiguous-roundtrip"
```

### Disambiguating using Leading-Tag Metadata

When serializer descriptors expose precise leading tags (`withAsn1LeadingTags` / `withDynamicAsn1LeadingTags`), awesn1 can
reason about field boundaries and accept otherwise risky nullable layouts.
This lets you keep reusable serializer components while still meeting strict schema disambiguation requirements.

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-leading-tags-custom-disambiguated-definitions"
```

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-leading-tags-custom-disambiguated-roundtrip"
```

1. {{ asn1js_iframe('kxs-leading-tags-custom-disambiguated') -}}
   Explore on <a href="{{ asn1js_url('kxs-leading-tags-custom-disambiguated') }}" target="_blank" rel="noopener">asn1js.eu</a>

Now one might ask: why is there no `ignoreUnknownElements` in the spirit of the Json format's `ignoreUnknownKeys`.
The reason is simple: it is not required **and** DER enforces strict rules to prevent ambiguities and ensure everything works
well in cryptographic contexts.
If you encounter a situation where this is needed, something is probably fishy and double-checking is recommended.
Should this **really** be needed, resort to [low-level ASN.1 decoding](lowlevel.md) and/or model data differently.

## See Also

- [Low-Level ASN.1 API](lowlevel.md): raw TLV/DER parse and decode utilities.
