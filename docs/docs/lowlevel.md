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
  Base type for all ASN.1 nodes (has `tag`, `contentLength`, `derEncoded`, pretty-print support).
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

## ASN.1-Specific Rich Types

The core module includes rich semantic types beyond raw TLV primitives:

- `Asn1Integer`: arbitrary-precision ASN.1 INTEGER handling.
- `Asn1Real`: ASN.1 REAL with arbitrary precision model and IEEE-754 bridges.
- `Asn1String` hierarchy: UTF8, Printable, IA5, BMP, Numeric, etc.
- `Asn1Time`: bridges `Instant` to UTC/Generalized Time.
- `Asn1BitString`: bit-level representation with padding-bit tracking.
- `BitSet`: pure-Kotlin bitset implementation.
- `ObjectIdentifier`: OID support (string/components/bytes/UUID-based constructors). See [Object Identifiers (OID) Deep Dive](#object-identifiers-oid-deep-dive).

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
3. Decode primitive content bytes into Kotlin/rich types.

### Parse Entry Points

- `Asn1Element.parse(source: ByteArray): Asn1Element`
- `Asn1Element.parseAll(source: ByteArray): List<Asn1Element>`
- `Asn1Element.parseFirst(source: ByteArray): Pair<Asn1Element, ByteArray>`
- `Asn1Element.parseFromDerHexString(derEncoded: String): Asn1Element`

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

## Debugging and Inspection

- `Asn1Element.prettyPrint()` and `Asn1Encodable.prettyPrintAsn1()` provide verbose human-readable trees.
- `Asn1Element.toDerHexString()` renders DER as hex.
- OID pretty printing can include names from `KnownOIDs` mappings.

## See Also

- [Serialization Tutorial](kxs.md): DER format via `kotlinx.serialization`.
