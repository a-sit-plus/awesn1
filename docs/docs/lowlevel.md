---
hide:
- navigation
---

# Low-Level ASN.1 API

This page is the detailed reference for awesn1 low-level APIs.

Use this page when you work directly with ASN.1 elements, tags, DER bytes, and primitive payload encoding/decoding.

For the data-class-first flow, see the [Serialization Tutorial](kxs.md).

## ASN.1 Model: Primitives vs Structures

awesn1 distinguishes two layers of abstraction:

- Generic ASN.1 elements:
  Raw TLV nodes (`Asn1Element`, `Asn1Primitive`, `Asn1Structure`) used when you parse bytes, inspect tags, assert structure, or build custom workflows.
- Rich semantic types:
  Domain-focused wrappers such as `Asn1Integer`, `Asn1Real`, `Asn1String`, `Asn1Time`, and `ObjectIdentifier` that add type-specific behaviour on top of primitive bytes.

When doing low-level ASN.1 work, you usually parse/build with generic elements first, then convert to semantic types where needed. See [ASN.1-Specific Rich Types](#asn1-specific-rich-types).  
More often than not, awesn1's [first-class kotlinx-serialization integration](kxs.md) will serve you better, because almost everything can be modelled using plain kotlin types.

### Base Model

- `Asn1Element`:
  Base type for all ASN.1 nodes (has `tag`, `contentLength`/`contentLengthLong`, `derEncoded`, pretty-print support).
- `Asn1Element.Tag`:
  Encodes tag number, tag class, and `CONSTRUCTED` bit.
- `Asn1Primitive`:
  A leaf element with raw `content: ByteArray`.
- `Asn1Structure`:
  A constructed element with `children: List<Asn1Element>`.

### Structure Implementations

- `Asn1Sequence`: ordered structure (`SEQUENCE`).
- `Asn1Set`: set semantics, DER sorting rules.
- `Asn1SetOf`: set semantics + same-tag constraint across children.
- `Asn1ExplicitlyTagged`: context-specific constructed wrapper.
- `Asn1CustomStructure`: custom-tagged structure (constructed or primitive semantics).
- `Asn1EncapsulatingOctetString`: `OCTET STRING` that contains ASN.1 children.

### Octet Strings

- `Asn1OctetString` is the abstraction.
- `Asn1PrimitiveOctetString` holds raw bytes.
- `Asn1EncapsulatingOctetString` holds child ASN.1 elements while still tagged as `OCTET STRING`.

## Deferred Semantic Parsing

awesn1 separates raw DER parsing from ASN.1 meaning. The parser first builds an `Asn1Element` tree from TLV bytes and
only enforces constraints needed to keep that raw tree well-bounded and DER-shaped. Type-specific validation happens
when you ask for semantics, for example by decoding a primitive as a boolean, integer, string, time, object identifier,
or custom data class.

At the raw parser layer, awesn1 rejects:

- indefinite length encoding, non-minimal long-form length encoding, length overflow, and child elements that overrun
  their parent
- high-tag-number encoding for tag numbers that belong in low-tag-number form (`<= 30`)
- universal tag `0` (end-of-contents) and universal tag `15`

Everything else is intentionally deferred. For example, a constructed universal UTF8String is not treated as a valid
UTF8String, but it can still be represented as an `Asn1CustomStructure` if its children form a valid raw ASN.1 tree.
Likewise, a primitive with a tag whose content is not meaningful for that tag can still be inspected as raw bytes.

Examples for semantic decoders are where ASN.1 meaning becomes strict:

- `readNull()` verifies that `NULL` has empty content.
- `decodeToBoolean()` requires one content byte and accepts only `0x00` or `0xff`.
- `Asn1Integer.decodeFromAsn1ContentBytes()` requires non-empty, minimally encoded INTEGER content.
- String, time, bit-string, object-identifier, and custom `Asn1Decodable` implementations perform their own
  type-specific checks.

This is useful for real-world interoperability work. You can parse malformed or quirky input into a raw tree, preserve
it for diagnostics or signature checks, and then define a semantic model that decides how strict to be. For example,
a data class can keep a private raw primitive for a legacy field and expose a public getter that normalizes one-byte
non-standard boolean values, while stricter code can keep using `decodeToBoolean()`.

## ASN.1-Specific Rich Types

The core module includes rich semantic types beyond raw TLV primitives:

- `Asn1Integer`: arbitrary-precision ASN.1 INTEGER handling.
- `Asn1Real`: ASN.1 REAL with arbitrary precision model and IEEE-754 bridges.
- `Asn1String` hierarchy: UTF8, Printable, IA5, BMP, Numeric, etc. See [ASN.1 String Types and Validation](#asn1-string-types-and-validation).
- `Asn1Time`: bridges `Instant` to UTC/Generalized Time.
- `Asn1BitString`: bit-level representation with padding-bit tracking.
- `BitSet`: pure-Kotlin bitset implementation.
- `ObjectIdentifier`: OID support (string/components/bytes/UUID-based constructors). See [Object Identifiers (OID) Deep Dive](#object-identifiers-oid-deep-dive).

## ASN.1 String Types and Validation

awesn1 models each ASN.1 restricted character-string type as a subtype of `Asn1String`. Consistent with
[Deferred Semantic Parsing](#deferred-semantic-parsing), **decoding from ASN.1 never validates the content**: the raw
bytes are preserved verbatim in `rawValue`, and `value` is always their UTF-8 interpretation. Validity is exposed
separately through `isValid: Boolean?`:

- `true` / `false` — the type implements a repertoire check.
- `null` — no validation is implemented for that type.

The `String` constructors (e.g. `Asn1String.IA5("…")`) are the only place that *enforces* validity: they throw
`Asn1Exception` when `isValid` would be `false`.

| Type            | Tag | Repertoire                                                | `isValid`       |
|-----------------|-----|-----------------------------------------------------------|-----------------|
| `UTF8`          | 12  | Any well-formed UTF-8 (ISO/IEC 10646, RFC 3629)           | exact           |
| `Numeric`       | 18  | Digits `0`–`9` and SPACE                                  | exact           |
| `Printable`     | 19  | `A`–`Z` `a`–`z` `0`–`9` SPACE `' ( ) + , - . / : = ?`     | exact           |
| `IA5`           | 22  | ITU-T T.50 / ISO 646, 7-bit `0x00`–`0x7F` (incl. DELETE)  | exact           |
| `Visible`       | 26  | T.50 graphic subset + SPACE, `0x20`–`0x7E`                | exact           |
| `Teletex` (T61) | 20  | ITU-T T.61 (multi-byte)                                   | best-effort (`true`/`null`) |
| `Graphic`       | 25  | ISO 2022 registered G-sets + SPACE                        | best-effort (`true`/`null`) |
| `General`       | 27  | ISO 2022 registered G/C-sets + SPACE + DELETE             | best-effort (`true`/`null`) |
| `Universal`     | 28  | UCS-4 / UTF-32                                            | none (`null`)   |
| `Videotex`      | 21  | T.100 / T.101 (obsolete)                                  | none (`null`)   |
| `Unrestricted`  | 29  | CHARACTER STRING                                          | none (`null`)   |
| `BMP`           | 30  | UCS-2 (UTF-16 BMP)                                        | none (`null`)   |

!!! warning "Validation limitations"

    * **`Teletex`, `Graphic`, and `General` are best-effort.** Their true repertoires are multi-byte / ISO 2022
      code sets that awesn1 does not fully model, so it only *recognizes* a fixed low-range subset (Latin-1
      `0x00`–`0xFF` for Teletex, 7-bit `0x20`–`0x7E` for Graphic, 7-bit `0x00`–`0x7F` for General). These types
      return `true` for recognized content and `null` ("unknown") for anything else, and **never return `false`** —
      so they never reject potentially-valid 8-bit or multi-byte input, and their `String` constructors never throw.
      A `true` is a positive recognition, not a guarantee of full-repertoire conformance.
    * **`Universal`, `Videotex`, `Unrestricted`, and `BMP` are never validated** (`isValid == null`). `rawValue` is
      preserved as-is; interpret it yourself if you need semantics.
    * **`UTF8.isValid` means "well-formed UTF-8", not "printable".** It deliberately accepts the replacement
      character U+FFFD (`EF BF BD`). Because any Kotlin `String` is UTF-8-encodable, the `UTF8(String)` constructor
      never rejects — byte-level well-formedness only matters for values decoded from ASN.1.

Repertoire definitions follow **ITU-T Rec. X.680 (ISO/IEC 8824-1) §41** and the underlying alphabets
([ITU-T T.50 / ISO 646](https://www.itu.int/rec/T-REC-T.50) for IA5/Visible; [RFC 3629](https://www.rfc-editor.org/rfc/rfc3629)
for UTF-8).

## Object Identifiers (OID) Deep Dive

### What an OID is

An ASN.1 `OBJECT IDENTIFIER` (OID) is a globally unique identifier in a hierarchical number tree, commonly written in dotted decimal notation:

- `1.2.840.113549`
- `2.5.4.3`
- `1.3.6.1.5.5.7`

Each number is called an arc (or node). The full path identifies exactly one object in the global OID namespace.

### Why OIDs are Instrumental

OIDs are the backbone of many ASN.1-based ecosystems because they provide stable, interoperable identifiers for semantics, not just bytes. They are used to identify:

- algorithms (for example signature/hash algorithms)
- attributes (for example X.509 distinguished name fields)
- extensions (for example certificate extensions)
- protocol message/object types
- vendor/private namespaces

Without OIDs, two systems might parse the same ASN.1 structure but disagree on meaning.

In awesn1 specifically, OIDs are also central to open polymorphism by identifier; see the serialization tutorial section [Open Polymorphism by OID](kxs.md#open-polymorphism-by-oid).

### Encoding Model (DER/BER content bytes)

ASN.1 OID content encoding is special:

1. The first two arcs are folded into one value: `40 * arc0 + arc1`.
2. Remaining arcs are encoded as base-128 varints.
3. The ASN.1 tag is universal `OBJECT IDENTIFIER` (`0x06`).

awesn1 handles this through `ObjectIdentifier` and its content-byte helpers.
For background on the historical encoding shape, see Microsoft's summary: [About Object Identifier](https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-object-identifier).

### awesn1 Validation and Behaviour

Current `ObjectIdentifier` validation enforces:

- empty OIDs are rejected
- at least two arcs are required for node-based construction
- first arc must be `0`, `1`, or `2`
- if first arc is `0` or `1`, second arc must be `< 40`
- for current implementation constraints, first-byte-form parsing also limits accepted first-subidentifier values to the current supported range

For invalid inputs, constructors/decoders throw `Asn1Exception`/`Asn1StructuralException`.

### Creating and Converting OIDs

`ObjectIdentifier` supports multiple entry points:

- `ObjectIdentifier(vararg nodes: UInt)` for numeric arcs
- `ObjectIdentifier("1.2.840.113549")` (also space-separated strings)
- `ObjectIdentifier(uuid)` for deterministic `2.25.<uuid-as-integer>` OIDs

Useful properties and conversions:

- `oid.bytes`: ASN.1 OID content bytes (not full TLV)
- `oid.nodes`: lazily decoded arc list
- `oid.toString()`: dotted decimal form

Encoding/decoding APIs:

- `ObjectIdentifier.encodeToTlv()`: wraps bytes in `Asn1Primitive(Tag.OID, ...)`
- `ObjectIdentifier.decodeFromAsn1ContentBytes(bytes)`
- `Asn1Primitive.readOid()`

### Human-Readable Naming (`KnownOIDs`)

`KnownOIDs` is a mutable mapping from `ObjectIdentifier` to description strings. It is intended for diagnostics and developer-facing output, not wire semantics.

- Add custom descriptions with `KnownOIDs[oid] = "..."`
- If the `oids` module is on your classpath, call `KnownOIDs.describeAll()` to preload common names
- Pretty-printing can use these names for easier debugging

### Serialization Behaviour

`ObjectIdentifier` has dual behaviour:

- with DER codecs, it encodes/decodes as ASN.1 `OBJECT IDENTIFIER`
- with non-DER serializers, it falls back to string form via `ObjectIdentifierStringSerializer`

## Raw ASN.1 Decoding

### Typical Pipeline

1. Parse DER bytes into `Asn1Element`.
2. Assert expected tags/structure.
3. Decode primitive content bytes into Kotlin/rich types, where semantic validation happens.

### Parse Entry Points

- `Asn1Element.parse(source: ByteArray): Asn1Element`
- `Asn1Element.parseAll(source: ByteArray): List<Asn1Element>`
- `Asn1Element.parseFirst(source: ByteArray): Pair<Asn1Element, ByteArray>`
- `Asn1Element.parseFromDerHexString(derEncoded: String): Asn1Element`

The `ByteArray` entry points are bounded by the array's size; the streaming `Source` overloads require an explicit byte
`limit`. For untrusted input, read [Hardening, Fuzzing & Robustness](hardening.md) first.
Parsing empty input throws `Asn1Exception` (these never return `null`).

Tag assertion helpers:

- `Asn1Element.assertTag(tag: Asn1Element.Tag)`
- `Asn1Element.assertTag(tagNumber: ULong)`

!!! example

    ```kotlin
    --8<-- "at/asitplus/awesn1/docs/CoreDocumentationHooksTest.kt:lowlevel-hook-parse-and-assert"
    ```

### High-level Decoding Contract (`Asn1Decodable`)

- Implement `doDecode(src)` for type-specific decoding.
- Optionally use/override `verifyTag(src, assertTag)`.
- Use `decodeFromTlv(src, assertTag)` for throwing decode.
- Use `decodeFromTlvOrNull(src, assertTag)` for non-throwing decode.
- Use `decodeFromDer(src, assertTag)` / `decodeFromDerOrNull(src, assertTag)` for direct DER decoding.

### Generic Primitive Decoder

- `Asn1Primitive.decode(assertTag: ULong, transform: (ByteArray) -> T): T`
- `Asn1Primitive.decode(assertTag: Asn1Element.Tag, transform: (ByteArray) -> T): T`
- `Asn1Primitive.decodeOrNull(tag: ULong, transform: (ByteArray) -> T): T?`

### `Asn1Primitive` Typed Decode Helpers

| Category       | Functions                                                                                                                                                                                                                                                                                                                                                            |
|----------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Boolean        | `decodeToBoolean`, `decodeToBooleanOrNull`                                                                                                                                                                                                                                                                                                                           |
| Integer family | `decodeToInt`, `decodeToIntOrNull`, `decodeToLong`, `decodeToLongOrNull`, `decodeToUInt`, `decodeToUIntOrNull`, `decodeToULong`, `decodeToULongOrNull`, `decodeToAsn1Integer`, `decodeToAsn1IntegerOrNull`                                                                                                                                                           |
| REAL family    | `decodeToAsn1Real`, `decodeToAsn1RealOrNull`, `decodeToDouble`, `decodeToDoubleOrNull`, `decodeToFloat`, `decodeToFloatOrNull`                                                                                                                                                                                                                                       |
| Enum family    | `decodeToEnumOrdinal`, `decodeToEnumOrdinalOrNull`, `decodeToEnum`, `decodeToEnumOrNull`                                                                                                                                                                                                                                                                             |
| String family  | `asAsn1String`, `decodeToUtf8String`, `decodeToUniversalString`, `decodeToIa5String`, `decodeToBmpString`, `decodeToTeletextString`, `decodeToPrintableString`, `decodeToNumericString`, `decodeToVisibleString`, `decodeToGeneralString`, `decodeToGraphicString`, `decodeToUnrestrictedString`, `decodeToVideotexString`, `decodeToString`, `decodeToStringOrNull` |
| Time           | `decodeToInstant`, `decodeToInstantOrNull`                                                                                                                                                                                                                                                                                                                           |
| Bit string     | `asAsn1BitString`                                                                                                                                                                                                                                                                                                                                                    |
| Null handling  | `readNull`, `readNullOrNull`                                                                                                                                                                                                                                                                                                                                         |

### Content-Byte Decode Helpers

These APIs decode only ASN.1 primitive payload bytes (no tag/length):

- `Int.decodeFromAsn1ContentBytes`
- `Long.decodeFromAsn1ContentBytes`
- `UInt.decodeFromAsn1ContentBytes`
- `ULong.decodeFromAsn1ContentBytes`
- `Boolean.decodeFromAsn1ContentBytes`
- `String.decodeFromAsn1ContentBytes`
- `Asn1Integer.decodeFromAsn1ContentBytes`
- `Asn1Real.decodeFromAsn1ContentBytes`
- `ObjectIdentifier.decodeFromAsn1ContentBytes`
- `Instant.decodeUtcTimeFromAsn1ContentBytes`
- `Instant.decodeGeneralizedTimeFromAsn1ContentBytes`

!!! Example
    
    ```kotlin
    --8<-- "at/asitplus/awesn1/docs/CoreDocumentationHooksTest.kt:lowlevel-hook-content-bytes"
    ```

## Raw ASN.1 Encoding

### Typical Pipeline

1. Start from a rich type or Kotlin primitive.
2. Produce `Asn1Element` (`encodeToTlv` or low-level primitive builders).
3. Materialize DER bytes (`derEncoded` or `encodeToDer`).

### High-level Encoding Contract (`Asn1Encodable`)

- Implement `encodeToTlv()`.
- Use `encodeToTlvOrNull()` for non-throwing behaviour.
- Use `encodeToDer()` / `encodeToDerOrNull()` for DER output.
- Use `withImplicitTag(...)` overloads on encodable types.

`Asn1Element.derEncoded` provides lazy DER encoding for all ASN.1 nodes.

### Primitive-Level Encoding Helpers

`encodeToAsn1Primitive()` is provided for:

- `Boolean`, `Int`, `Long`, `UInt`, `ULong`
- `Enum<*>`
- `Asn1Integer`, `Asn1Real`
- `Double`, `Float` (`OrNull` variants available)
- `String` (UTF-8 ASN.1 string)

### Content-Byte Encoding Helpers

`encodeToAsn1ContentBytes()` is provided for:

- `Boolean`, `Int`, `Long`, `UInt`, `ULong`
- `Enum<*>`
- `Asn1Integer`
- `Asn1Real` (member function)

### Specialized Encoding Helpers

- `ByteArray.encodeToAsn1OctetStringPrimitive()`
- `ByteArray.encodeToAsn1BitStringPrimitive()`
- `ByteArray.encodeToAsn1BitStringContentBytes()`
- `Instant.encodeToAsn1UtcTimePrimitive()`
- `Instant.encodeToAsn1GeneralizedTimePrimitive()`

## Tagging: EXPLICIT and IMPLICIT

- EXPLICIT tagging wraps one or more children in a constructed context-specific container.
- IMPLICIT tagging replaces an element tag (with explicit control over class/constructed template).

Useful helpers:

- `Asn1.ExplicitlyTagged(tagNumber) { ... }`
- `Asn1.ExplicitTag(tagNumber)`
- `Asn1.ImplicitTag(tagNumber, tagClass)`
- `element withImplicitTag (...)`
- `tagNumber withClass TagClass.*`
- `tagNumber without CONSTRUCTED`

## ASN.1 Builder DSL Reference

Main DSL constructors under `Asn1`:

- Structures:
  `Sequence`, `SequenceOrNull`, `SequenceSafe`, `Set`, `SetOrNull`, `SetSafe`, `SetOf`, `SetOfOrNull`, `SetOfSafe`, `ExplicitlyTagged`, `ExplicitlyTaggedOrNull`, `OctetStringEncapsulating`
- Primitive builders:
  `Bool`, `Int` (all integer overloads), `Real` (float/double), `Enumerated`, `OctetString`, `BitString`, `Utf8String`, `PrintableString`, `Null`, `UtcTime`, `GeneralizedTime`

Inside a builder, unary `+` accepts raw `Asn1Element` values and `Asn1Encodable` values. Transparent wrapper types can
also participate without exposing their backing value at each call site:

- `WrappedElement<T>` appends its `element` directly.
- `WrappedEncodable<T>` encodes its `value` and appends the resulting TLV element.

Use these marker interfaces only when the wrapper has exactly the same ASN.1 representation as the exposed value.
For example, the `crypto` module's `X509AlgorithmIdentifier` wraps an `Asn1Sequence`, while `X509SignatureValue` wraps an
`Asn1BitString`; both can therefore be added without a serialization context:

```kotlin
val sequence = Asn1.Sequence {
    +algorithmIdentifier
    +signatureValue
}
```

To add arbitrary `@Serializable` values instead, use the `kxs` integration described in
[Serializable Values in the Builder DSL](kxs.md#serializable-values-in-the-builder-dsl).

!!! Example "Basic DSL"
    
    ```kotlin
    --8<-- "at/asitplus/awesn1/docs/CoreDocumentationHooksTest.kt:core-hook-builder"
    ```
    
    1. {{ asn1js_iframe('core-hook-builder') -}}
   Explore on <a href="{{ asn1js_url('core-hook-builder') }}" target="_blank" rel="noopener">asn1js.eu</a>

!!! Example "Expanded Tagging"
    
    ```kotlin
    --8<-- "at/asitplus/awesn1/docs/CoreDocumentationHooksTest.kt:lowlevel-hook-dsl-tagging"
    ```
    
    1. {{ asn1js_iframe('lowlevel-hook-dsl-tagging') -}}
   Explore on <a href="{{ asn1js_url('lowlevel-hook-dsl-tagging') }}" target="_blank" rel="noopener">asn1js.eu</a>

## Robustness, Limits, and Hostile Input

awesn1's raw parser, encoder, and renderers are designed to fail predictably on adversarial input: a malformed or
deliberately oversized/deeply-nested DER blob yields a bounded `Asn1Exception` or a bounded result — never a
`StackOverflowError`, runaway recursion, or silent corruption.

The full robustness model (iterative parsing/encoding/rendering, `Int`/`Long` length guards, bounded
depth and collection counts, catchable-errors-only, the fuzzing/audit coverage behind it, the caller's
input-bounding responsibility, and the residual `kotlinx.serialization` footguns) is presented in [Hardening, Fuzzing & Robustness](hardening.md).

## Performance

awesn1's raw TLV layer aims for predictable, allocation-light parsing and encoding while staying fully iterative and
multiplatform. The JMH microbenchmarks below pit the raw `Asn1Element` layer against Bouncy Castle's `ASN1Primitive`,
and measure the cost of the length walk, string rendering, and SET sorting.

!!! note "Benchmark environment"

    JMH 1.37, average-time mode (**lower is better**), 1 thread, 3×10 s warmup + 5×10 s measurement, single fork, JDK 17
    (Corretto 17.0.10). MacBook Pro (Apple **M3**, 12 cores: 6 performance + 6 efficiency), macOS 26.5.1, on AC power.
    These are microbenchmark figures — indicative, not contractual; re-run `./gradlew :benchmarks:jmh` on your own
    hardware. Bouncy Castle is a mature, hand-tuned baseline; awesn1 trades a little raw throughput for a fully
    iterative, hardened, multiplatform implementation.

Fixtures: **cert** = a real self-signed X.509 v3 certificate; **integers** = a `SEQUENCE` of 50 `INTEGER`s;
**mixed** = a small `SEQUENCE { INTEGER, OCTET STRING(32), BOOLEAN }`.

### Raw TLV Decode / Encode vs Bouncy Castle

| Operation (µs/op)                          |        cert |    integers |       mixed |
|--------------------------------------------|------------:|------------:|------------:|
| awesn1 decode                              | 3.848 ±0.02 | 4.368 ±0.12 | 1.119 ±0.02 |
| Bouncy Castle decode                       | 2.072 ±0.17 | 1.108 ±0.01 | 0.131 ±0.00 |
| awesn1 encode (warm, recomputes each call) | 1.133 ±0.03 | 1.073 ±0.01 | 0.143 ±0.01 |
| Bouncy Castle encode                       | 1.250 ±0.02 | 0.455 ±0.00 | 0.070 ±0.00 |
| awesn1 round-trip (cold: parse + encode)   | 5.304 ±0.15 | 5.429 ±0.08 | 1.434 ±0.02 |
| awesn1 `derEncoded` access (recomputes)    | 0.772 ±0.01 | 0.807 ±0.01 | 0.176 ±0.01 |

The raw parser decodes in the low-single-digit-microsecond range — roughly 1.5–2× Bouncy Castle on the realistic
certificate fixture (more on the tiny integer/mixed fixtures, where fixed per-element overhead dominates a sub-microsecond
absolute cost). Warm stream-encoding is competitive with, and on the certificate faster than, BC. Note that, by design,
structures do **not** retain their encoding ([Re-encoding is deliberate](hardening.md)): repeated `derEncoded` access
recomputes `O(size)` each time, which the `derEncoded access` row quantifies as the accepted cost of stack-safe,
copy-free structures.
In addition, awesn1 always decodes any OCTET STRING's content bytes that are valid DER-encoded ASN.1 data, as this pattern
is so common in practice. This incurs overhead, but allows for asserting encapsulating OCTET STRINGs containing valid
ASN.1 data during parsing.

### Length Walk, Rendering, SET Sorting

| Operation (µs/op)                                |         cert |    integers |       mixed |
|--------------------------------------------------|-------------:|------------:|------------:|
| `parse` only                                     |  3.814 ±0.11 | 4.700 ±0.07 | 1.235 ±0.01 |
| `parse` + `overallLengthLong` (cold length walk) |  4.710 ±0.02 | 4.158 ±0.04 | 1.276 ±0.03 |
| `toString()` (compact)                           | 11.141 ±0.68 | 8.357 ±0.05 | 1.042 ±0.01 |
| `prettyPrint()`                                  | 12.566 ±0.39 | 8.491 ±0.12 | 1.105 ±0.01 |

The content-length walk is a stack-safe post-order pass; `parseThenLength − parseOnly` puts it around one microsecond
on the certificate and below a tenth of a microsecond on the mixed fixture. The separately measured integer result is
lower with the length walk, so its subtraction is not meaningful. Rendering is uncached and bounded (see
[Hardening → bounded rendering](hardening.md)).


### Real-World Corpus Sweep vs Bouncy Castle

One invocation sweeps the entire real-world DER/PEM corpus shipped in `crypto/src/jvmTest/resources` (certificate
fixtures, attestation chains, real TLS certificates) once; both libraries pay an identical `runCatching` wrapper so the
comparison stays fair.

| Operation (µs/op, full sweep) |            Score |
|-------------------------------|-----------------:|
| awesn1 decode                 | 4658.056 ± 34.28 |
| Bouncy Castle decode          | 2690.705 ± 10.04 |
| awesn1 encode                 | 1437.832 ± 17.93 |
| Bouncy Castle encode          | 1232.552 ±129.85 |

## Memory

A parsed ASN.1 value is an in-memory object graph, so it occupies several times the DER bytes it was decoded from. That
**amplification factor** — not the wire size — is what to keep in mind when sizing untrusted input
(see [Hardening → input bounding](hardening.md#input-bounding-as-the-callers-responsibility)). The figures below hold
the parsed representation of the whole real-world certificate/attestation corpus
(`crypto/src/jvmTest/resources`, **690 DER blobs ≈ 0.63 MiB**) and compare the retained heap across three forms.

| Held representation                       | parsed | retained heap | vs raw DER |
|-------------------------------------------|-------:|--------------:|-----------:|
| awesn1 raw `Asn1Element` tree             |    690 |    ~15.0 MiB  |    ~23.8×  |
| awesn1 typed `X509Certificate` (`kxs`)    |    664 |     ~5.9 MiB  |     ~9.6×  |
| Bouncy Castle `X509Certificate` (JCA)     |    652 |     ~3.3 MiB  |     ~5.6×  |

The generic `Asn1Element` tree is the heaviest representation — it keeps a node wrapper, a tag, and a child container
per TLV element, which is the most flexible but least compact form. awesn1's typed [`kxs`](kxs.md) model collapses that
into purpose-built data classes (~2.5× leaner than the raw tree) and lands within ~2× of Bouncy Castle's hand-written
X.509 model. Note that the peak memory consumption while parsing will be the sum of the raw tree's memory consumption
and the typed `X509Certificate` model's.
Once the final certificate is constructed, the raw tree is free for garbage collection.

!!! note "Method & caveats"

    Each form is the **retained heap** (used heap after `System.gc()`,
    cross-checked with VisualVM heap dumps) holding only the parsed objects — the raw input bytes are dropped before
    measuring. awesn1's typed model and Bouncy Castle accept slightly different cert subsets (664 vs 652), so each ratio
    uses its own parsed-byte denominator. Figures are indicative (GC/JIT/JVM-version sensitive). Reproduce with the
    `NestingMemory` probe under `core/src/jvmTest`.

## Debugging and Inspection

- `Asn1Element.prettyPrint()` and `Asn1Encodable.prettyPrintAsn1()` provide verbose human-readable trees. Output is
  length-bounded and truncated for very large/deep trees (see [above](#string-rendering-is-bounded)).
- `Asn1Element.toDerHexString()` renders DER as hex.
- OID pretty printing can include names from `KnownOIDs` mappings.

## See Also

- [Serialization Tutorial](kxs.md): DER format via `kotlinx.serialization`.
