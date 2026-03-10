---
hide:
- navigation
---

# Addons

In addition to core functionality, awesn1 provides three out-of-the-box addons:

1. Integration with kotlinx-io
2. DER+kotlinx.serialization integration on top of kotlinx-io
3. A plethora of standardised, known object identifiers

## ![io.svg](assets/io.svg) {: #io data-toc-label="IO" }
The awesn1 core module works on byte arrays. IO-oriented support is provided through kotlinx-io integration using the
`io` module.

### Maven Coordinates

```kotlin
implementation("at.asitplus.awesn1:io:$version")
```

### Features

- `kotlinx.io.Source` integration for ASN.1 parsing:
  `Asn1Element.parse(source)`, `parseAll(source)`, `parseFirst(source)`, `source.readAsn1Element()`.
- `kotlinx.io.Sink` integration for DER encoding:
  `asn1Value.encodeToDer(sink)`.
- Primitive ASN.1 content helpers directly on `Source`/`Sink`:
  `readAsn1…Content(...)` and `writeAsn1…Content(...)` for booleans, numbers, strings, reals, and time values.
- VarInt and two's-complement helpers:
  `writeAsn1VarInt(...)`, `decodeAsn1VarUInt()/decodeAsn1VarULong()`,
  `readTwosComplement...(...)`, `writeTwosComplement...(...)`.

### Source/Sink Integration Sketches

Decode one ASN.1 element from a `Source`:

```kotlin
val source = Buffer().apply { write(derBytes) }
val (element, consumed) = source.readAsn1Element()
```

Encode an `Asn1Encodable` value to a `Sink`:

```kotlin
val sink = Buffer()
myAsn1Value.encodeToDer(sink)
val derBytes = sink.readByteArray()
```

### Primitive Content Helpers (Sink/Source)

Boolean content:

```kotlin
val b = Buffer()
b.writeAsn1BooleanContent(true)
val value = b.readAsn1BooleanContent() // true
```

Integer content:

```kotlin
val n = Buffer()
val nBytes = n.writeAsn1IntContent(42)
val value = n.readAsn1IntContent(nBytes) // 42
```

String content:

```kotlin
val s = Buffer()
val sBytes = s.writeAsn1StringContent("hello")
val value = s.readAsn1StringContent(sBytes) // "hello"
```

!!! note "Reading Content Bytes"
    Note that `readAsn1…Content(nBytes)` helpers consume ASN.1 *content octets* (not a full TLV),
    so pass the expected content length.

## ![kxs-io.svg](assets/kxs-io.svg) {: #kxs-io data-toc-label="KXS-IO" }

`kxs-io` contains kotlinx-io extensions for awesn1's DER `kotlinx.serialization` format.

### Maven Coordinates

```kotlin
implementation("at.asitplus.awesn1:kxs-io:$version")
```

### Integration with `kotlinx.serialization`

```kotlin
val oid = ObjectIdentifier("1.2.840.113549.1.1.11")

// Encode directly to a kotlinx.io.Sink using DER + kxs-io extension
val sink = Buffer()
DER.encodeToSink(oid, sink)

// Decode directly from a kotlinx.io.Source using DER + kxs-io extension
val source = Buffer().apply { write(sink.readByteArray()) }
val decoded: ObjectIdentifier = DER.decodeFromSource(source)
```

## ![oids.svg](assets/oids.svg) {: #oids data-toc-label="OIDs" }

The `oids` module is literally [Peter Gutmann](https://www.cs.auckland.ac.nz/~pgut001/#standards)'s `dumpasn1.cfg`
transformed into a Kotlin extensions on the awesn1 core module's `KnownOIDs` object.
In fact, the ability to do just that is the reason this object is part of the core module at all.

### Maven Coordinates

```kotlin
implementation("at.asitplus.awesn1:oids:$version")
```

### Features

- Generated known OID constants as extension properties on `KnownOIDs`.
  This gives discoverable names such as `KnownOIDs.date`, `KnownOIDs.countryName`, etc., each returning an `ObjectIdentifier`.
- Human-readable descriptions are stored in `KnownOIDs` (a mutable map from `ObjectIdentifier` to `String`).
- `KnownOIDs.describeAll()` bulk-loads all descriptions shipped by the `oids` module.
  The first call initialises the map; subsequent calls are effectively no-ops.
- You can add or override your own labels at runtime:
  `KnownOIDs[myOid] = "My Domain OID"`.
- Pretty-print integration:
  when an ASN.1 primitive with tag `OID` is pretty-printed, awesn1 checks `KnownOIDs[oid]`.
  If a description exists, output is `Description (1.2.3...)`; otherwise it falls back to the plain numeric OID.

### Working with Known OIDs

Use named OID constants (extension properties):

```kotlin
val oid = KnownOIDs.date
```

Load bundled descriptions and query them:

```kotlin
KnownOIDs.describeAll()
val description = KnownOIDs[KnownOIDs.date] // returns human-readable descriptions
```

Add your own description:

```kotlin
val expressionistOID = ObjectIdentifier(Uuid.random())

KnownOIDs[expressionistOID].shouldBeNull()
KnownOIDs[expressionistOID] = "Edvard Munch"
KnownOIDs[expressionistOID] shouldBe "Edvard Munch"
```

All described known OIDs are used when `prettyPrint`ing `Asn1Element`s. This can prove helpful for debugging, but 
`describeAll` should not be used in memory-constrained environments (such as iOS app extensions), because it will increase
resident memory consumption by a couple of megabytes.
