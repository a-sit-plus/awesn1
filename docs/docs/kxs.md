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
- A `Der` instance itself stays immutable; only the pre-initialization contributor list is extensible

Typical reasons to add contributors are domain-specific open polymorphism and raw-backed semantic wrappers.
Functionally, the registry is just a pre-initialization list of `SerializersModule`s that are merged into the
default `DER` instance during its lazy initialization.

One realistic example is CMS or PKI open types that are dispatched by OID. If your application introduces a custom
CMS-style attribute value family and wants raw-backed models to decode those values through the default `DER`
instance, register that serializers module up front.

Type definition (a single type implementing the base interface for compactness):
```kotlin
--8<-- "at/asitplus/awesn1/serialization/docs/DefaultDerRegistryDocumentationTest.kt:kxs-default-der-registry-definitions"
```

Registration:
```kotlin
--8<-- "at/asitplus/awesn1/serialization/ModuleTestSession.kt:kxs-default-der-registry-setup"
```

The default DER instance then knows the custom type hierarchy:
```kotlin
--8<-- "at/asitplus/awesn1/serialization/docs/DefaultDerRegistryDocumentationTest.kt:kxs-default-der-registry-usage"
```

The important part is that the registration happens before the first access to `DER`.

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

## Serializable Values in the Builder DSL

The `kxs` module lets an `Asn1TreeBuilder` encode values whose static type has an available kotlinx serializer. Use a
`Der` instance as context parameter and use unary `+`; the serializer is inferred from that static type:

```kotlin
val envelope = with(DER) {
    Asn1.Sequence {
        +certificate
    }
}
```

Here `certificate` may be an `@Serializable` application type or, for example, the `X509Certificate` model from the
`crypto` module. The encoded certificate is appended as one child TLV element; the surrounding `Asn1.Sequence` remains
an additional outer sequence.

The equivalent explicit builder calls are:

```kotlin
Asn1.Sequence {
    append(certificate, DER)                       // inferred serializer
    append(X509Certificate.serializer(), other, DER) // explicit serializer
}
```

Nullable values follow the selected `Der` configuration. If encoding omits a nullable `null` because
`explicitNulls` is disabled, the builder appends nothing.

Core builder operands do not need a `Der` context. `Asn1Element`, `Asn1Encodable`, `WrappedElement`, and
`WrappedEncodable` values work directly with unary `+`; they continue to work unchanged inside `with(DER)`. In
particular, the `crypto` module's `X509AlgorithmIdentifier` and `X509SignatureValue` are transparent wrappers:

```kotlin
val withoutContext = Asn1.Sequence {
    +algorithmIdentifier
    +signatureValue
}

val withContext = with(DER) {
    Asn1.Sequence {
        +algorithmIdentifier
        +signatureValue
    }
}
```

Both forms append the wrappers' existing ASN.1 representation. A `Der` context is required only for values that need
the serialization bridge.

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

## Inline/Value Classes
Inline/value classes are invisible to the format. Hence, wrapping anything in a value class has no effect on the resulting bytes.
As such, creating a regular class with a single property wraps that property in an ASN.1 `SEQUENCE` with a single child, whilst wrapping
anything in a value class results in the same ASN.1 representation as directly encoding it.

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


!!! warning "Tagging Inline Classes"
    For regular serializable classes, put `@Asn1Tag` on the class or on the property whose ASN.1 field needs the override.
    For Kotlin inline/value classes, put `@Asn1Tag` on the inline/value class declaration itself. Do not put it on the
    single backing property: inline/value class unwrapping removes that property boundary, so awesn1 rejects such models
    with `SerializationException` instead of silently choosing an ambiguous tag.  
    **In summary:**
    
    * Outermost tag wins for inline classes
    * Tagging a property of an inline class is illegal and rejected
    * Tags on the class (default or manually specified on class declaration) are respected, if no tag annotation is present on an inline class
    

    The following is therefore illegal:
    
    ```kotlin
    --8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-inline-valueclass-tag-definitions-rej"
    ```
    
    ```kotlin
    --8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-inline-valueclass-tag-roundtrip-rej"
    ```

    1. `TutorialDocInvalidBackingTaggedByte` is rejected because the tag is attached to the inline backing property.


Applying this rule to scalar wrappers modelled as Kotlin value classes exemplifies this:

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-inline-valueclass-tag-definitions"
```

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-inline-valueclass-tag-roundtrip"
```

1. {{ asn1js_iframe('kxs-inline-valueclass-tag') -}}
   Explore on <a href="{{ asn1js_url('kxs-inline-valueclass-tag') }}" target="_blank" rel="noopener">asn1js.eu</a>
   `TutorialDocTaggedByte` is encoded as private tag 18 (`d2`) over the integer payload.

When an inline/value class wraps a type that already has an implicit class tag, the inline/value class tag is the
outer schema contract and takes precedence:

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-inline-valueclass-outer-tag-definitions"
```

```kotlin
--8<-- "at/asitplus/awesn1/serialization/tutorial/SerializationDocumentationTutorialTest.kt:kxs-inline-valueclass-outer-tag-roundtrip"
```

1. {{ asn1js_iframe('kxs-inline-valueclass-outer-tag') -}}
   Explore on <a href="{{ asn1js_url('kxs-inline-valueclass-outer-tag') }}" target="_blank" rel="noopener">asn1js.eu</a>
   `TutorialDocTaggedOuter` is encoded with private tag 18 (`f2`); the wrapped class' private tag 19 (`f3`) is not used.
2. Decoding the inner class tag at this position fails, because the inline/value class tag is expected.

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

`ExplicitlyTagged<T>` can also be used as a property delegate when reading model objects.
The delegated property unwraps the contained value while preserving Kotlin's inferred type; nullable wrappers unwrap
to nullable values.

```kotlin
@Asn1Tag(tagNumber = 0u)
val taggedVersion: ExplicitlyTagged<Asn1Integer>? = null

val actualTaggedVersion by taggedVersion // Asn1Integer?
```

Use `orValue(default)` when an absent wrapper should read as a non-null default while keeping delegate syntax.

```kotlin
val effectiveHashAlgorithm by hashAlgorithm.orValue(SHA1_IDENTIFIER)
```

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
For inline/value-class alternatives, place those annotations on the value class declaration, not on the backing property.

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

### Tagged CHOICE Values

Do not put `@Asn1Tag` on a sealed `CHOICE` type or on a property whose type is a sealed `CHOICE`.
awesn1 rejects this because ASN.1 implicit tagging replaces the tag of an existing TLV, but `CHOICE` has no tag of
its own. Only the selected alternative has a tag. Retagging that selected alternative would change the alternative
itself instead of tagging the `CHOICE` value, and can produce invalid DER or make decoding ambiguous.

This matters in real profiles. X.509 defines `GeneralName` and `Name` like this:

```asn1
GeneralName ::= CHOICE {
  dNSName         [2] IA5String,
  directoryName  [4] Name
}

Name ::= CHOICE {
  rdnSequence RDNSequence
}
```

`dNSName [2] IA5String` can be modeled as an implicitly tagged primitive alternative, because `IA5String` has a tag
that can be replaced. `directoryName [4] Name` is different: `Name` is itself a `CHOICE`, so there is no `Name` tag to
replace. The wire shape must be a context-specific constructed `[4]` wrapper containing the selected `Name`
alternative, for example the `rdnSequence` `SEQUENCE`.

Model this kind of schema as an explicit wrapper in Kotlin, with `ExplicitlyTagged<T>` or with a small
domain-specific wrapper.
Do not model it as `@Asn1Tag(4u)` on the sealed `Name` type or on a `Name` property.

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
When the variant is a value class, its implicit tag belongs on the value class declaration.

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
2. {{ asn1js_iframe('kxs-open-poly-oid-catchall') -}}
   Explore on <a href="{{ asn1js_url('kxs-open-poly-oid-catchall') }}" target="_blank" rel="noopener">asn1js.eu</a>

### Provided-Fallback Types

An extensible model can provide a structural serializer for use when the active `Der` instance has no contextual
open-polymorphism registration. Subclass `Asn1OpenPolymorphicWithDefaultSerializer` from the serializer object named
by `@Serializable(with = ...)`. Its default serializer commonly uses an OID `catchAll` that retains the discriminator
and raw or otherwise generic payload.

```kotlin
--8<-- "at/asitplus/awesn1/serialization/SerializationOpenPolymorphismByOidTest.kt:kxs-open-poly-default-definitions"
```

With an unconfigured `Der`, the provided-fallback serializer handles the value. A contextual `polymorphicByOid`
registration on a custom `Der` takes precedence and enables custom subtypes. Include the structural `catchAll` in
that contextual registration as well if the configured instance must continue accepting unknown OIDs.

```kotlin
--8<-- "at/asitplus/awesn1/serialization/SerializationOpenPolymorphismByOidTest.kt:kxs-open-poly-default-usage"
```

The same override works with the default `DER` instance through the [Default `DER` Registry](#default-der-registry).
Call `DefaultDer.register(...)` during application or library startup, before the first access to the lazily initialized
`DER` value. If nothing is registered, the provided-fallback type is used automatically.

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
For example, production implementations exist that misencode `TRUE` or show other low-level flaws
(see
[encoding flaws documented by Warden Supreme](https://a-sit-plus.github.io/warden-supreme/technical/quirks/#encoding-flaws) for real-world examples at scale).
Hence, we model the signed box using a raw ASN.1 structure and don't care for such details.

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


## Format Options

DER format behaviour can be tuned with the DER builder:

- `explicitNulls = true`: encode nullable `null` as ASN.1 `NULL`
- `encodeDefaults = false`: omit default-valued properties
- `maxInputLength = …`: maximum number of encoded DER bytes to consume before refusing to parse (enforced before
  reading from the source)

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

!!! danger "Bound untrusted input with `maxInputLength`"
    
    `maxInputLength` defaults to `Int.MAX_VALUE` (~2 GiB). This keeps every decoded element's lengths `Int`-sized (so
    parsing and re-encoding stay fully `Int`-based), but it is **not** a small safety cap: decoding parses into an
    in-memory tree, so input size bounds memory. When decoding untrusted data — especially from a `Source` —
    **lower `maxInputLength`** to a value appropriate to your payload. Raise it past `Int.MAX_VALUE` only to deliberately
    handle multi-gigabyte input (which requires a `Source`, since a `ByteArray` cannot exceed `Int.MAX_VALUE` bytes). See
    [Hardening, Fuzzing & Robustness](hardening.md) for the full picture.
    
    When decoding from a `Source` (`kxs-io`), `decodeFromSource(..., limit = …)` accepts a per-call byte `limit`. It
    defaults to `maxInputLength` and is **clamped** to it — a per-call `limit` can only *tighten* the bound, never raise
    it above the configured maximum (just as a shorter `ByteArray` lowers the effective bound when decoding from bytes).

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

## Performance

The `kxs` layer builds a **typed object graph** on top of the raw TLV layer, so it pays the
`kotlinx.serialization` decode/encode machinery in addition to the parse/encode cost. The benchmark below decodes and
re-encodes a real self-signed X.509 v3 certificate through `DER.decodeFromByteArray`/`encodeToByteArray` (into a
`@Serializable` certificate model) and compares against Bouncy Castle's hand-written, typed `x509.Certificate` model.

??? note "Benchmark environment"

    JMH 1.37, average-time mode (**lower is better**), 1 thread, 3×10 s warmup + 5×10 s measurement, single fork, JDK 17
    (Corretto 17.0.10). MacBook Pro (Apple **M3**, 12 cores: 6 performance + 6 efficiency), macOS 26.5.1, on AC power.
    These are microbenchmark figures - indicative, not contractual; re-run `./gradlew :benchmarks:jmh` on your own
    hardware. Bouncy Castle is a mature, hand-tuned baseline; `kxs` trades some speed for declarative,
    `kotlinx.serialization`-native modelling. For the raw-layer numbers underneath this, see
    [Low-Level → Performance](lowlevel.md#performance).

| Operation (X.509 certificate)      | Score (µs/op) |
|------------------------------------|--------------:|
| awesn1 `kxs` decode → typed model  | 12.071 ±0.079 |
| Bouncy Castle decode → typed model |  2.105 ±0.017 |
| awesn1 `kxs` encode ← typed model  |  6.483 ±0.119 |
| Bouncy Castle encode ← typed model |  1.292 ±0.010 |

Reading the numbers: the declarative `kxs` model decodes a certificate in ~12 µs and re-encodes it in ~6.5 µs – single-
digit-to-low-double-digit microseconds, i.e. tens of thousands of certificates per second per core, while letting you
work with plain `@Serializable` Kotlin types instead of a bespoke ASN.1 model. The hand-written Bouncy Castle model is
significantly faster in absolute terms, but lacks the convenience and multiplatform support.

### Memory

In memory, the typed `kxs` `X509Certificate` model is markedly more compact than the raw `Asn1Element` tree (it collapses
generic TLV wrappers into purpose-built data classes) and lands within ~2× of Bouncy Castle's hand-written X.509 model
on the real-world certificate corpus. See the full three-way comparison vs. raw DER bytes in
[Low-Level → Memory](lowlevel.md#memory).

## See Also

- [Low-Level ASN.1 API](lowlevel.md): raw TLV/DER parse and decode utilities.
- [Hardening, Fuzzing & Robustness](hardening.md): robustness model and `kxs` residual footguns.
