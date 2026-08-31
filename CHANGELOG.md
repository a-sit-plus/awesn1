# Changelog

## NEXT
* Add an experimental ASN.1 JS viewer
    * Render the full Android key attestation schema: KeyMint/Keymaster enumerations, packed version and
      patch-level integers, date tags, identifier strings, and the nested `AttestationApplicationId`
    * Schema hints are now strictly decorative: anything that parses as ASN.1 renders, falling back to the generic
      tree when semantic enrichment does not apply or fails
* Updates dumpasn1 Known OIDs to 8 January 2026 with oh-so-many-more OIDs

## 0.8.0
* Moved the faux-constructor extensions on `SubjectPublicKeyInfo` to `from` extensions
    * This avoids pathological autocomplete behavior
* Added `Sec1EcPublicKeyInfo` to match `Pkcs1RsaPublicKeyInfo`
* Usability improvements to `Asn1BitString`
    * Added indexing operators and size
    * Added utility constructor from vararg bits
* Usability improvements to `Pkcs8PrivateKeyInfo`
    * Defaulted `version` to `V1` in the constructor

## 0.7.0
* **Security Hardening:**
    * Harden INTEGER/OID decimal conversion against DoS [Hardening → Bounded Numeric Conversion](hardening.md):
        * Added `Asn1Integer.toLong()`/`toLongOrNull()`
        * `Asn1Integer.fromDecimalString()` and `Asn1Integer.toDecimalString()` now have input size limits
          (with reasonable defaults)
            * `Asn1IntegerDecimalStringSerializer`'s limits can be overridden manually (and globally) if desired
            * DER encoding/decoding is unaffected by this change.
              It **only** pertains to explicit decimal conversion.
        * `Asn1Integer`'s string representation and default fallback serializer now use hex notation (with `-` prefixed for negative values).
          `toString()` is bounded, prefixes truncated output with `[truncated, N bytes total]`, renders at most 48 magnitude bytes, and never throws; `toHexString()` and serialization remain exact.
        * `Asn1Real`'s finite string representation and fallback serializer now use a hexadecimal mantissa and exponent.
          `toString()` uses the same bounded mantissa rendering as `Asn1Integer`; serialization remains exact. Special values render as `0.0`, `-0.0`, `INF`, `-INF`, or `NaN`.
    * Fix resource hog when decapsulating OCTET STRINGs through array views (addresses [GHSA-q34j-33q7-fw9h](https://github.com/a-sit-plus/awesn1/security/advisories/GHSA-q34j-33q7-fw9h))
* **Fixes:**
    * Fixed PKCS#10 attribute canonicalisation: programmatically created attribute sets are DER-sorted, while decoded
      `rawAttributes` and `rawValue` retain malformed wire order and duplicates for lenient parsing.
    * Added `LenientSet`, a serializable ASN.1 `SET OF` collection that accepts only Kotlin sets when constructed,
      preserves decoded wire contents when re-encoded, and exposes `toValidatedSet()` for duplicate validation.
    * Decoding an ASN.1 `SET OF` into Kotlin `Set<T>` now throws instead of silently discarding duplicate elements.
    * PKCS#10 semantic `attributes` and `value` getters now reject malformed decoded duplicates; empty attribute values,
      duplicate attribute OIDs, and empty extension requests are rejected during programmatic construction.
    * Allow `Asn1` builder unary `+` for transparent wrappers around `Asn1Element`/`Asn1Encodable`, and for serializable
      values when a `Der` instance is in context.
* **Other Changes:**
    * Change the `X509AlgorithmIdentifier` constructor to take a single nullable `parameters` element.
        * Previously, it took a `List` that could only reasonably have 0-1 elements, enforced by the `parameters` getter. Deprecated that constructor variant.
    * Clean up algorithm-specific parsers and move them out of the generic element they parse
        * `RsaSsaPssParams`:
            * `X509AlgorithmIdentifier.rsaSsaPssParams` -> `RsaSsaPssParams.of(X509AlgorithmIdentifier)`
            * new extension on `RsaSsaPssParams` companion: `X509AlgorithmIdentifier(RsaSsaPssParams)`
        * `EcdsaSigValue`:
            * new class: `EcdsaSigValue` models `ECDSA-Sig-Value` from RFC 5480
            * `X509SignatureValue.decodeRS()` in class -> `X509SignatureValue.toEcdsaSigValue()` on `EcdsaSigValue` companion
            * `X509SignatureValue.fromRS()` -> `EcdsaSigValue.toX509SignatureValue()`
        * `Pkcs1RsaPublicKeyInfo`:
            * `SubjectPublicKeyInfo.decodeRsaPublicKey()` -> `Pkcs1RsaPublicKeyInfo.of(SubjectPublicKeyInfo)`
            * `SubjectPublicKeyInfo.rsa(...)` -> `SubjectPublicKeyInfo(...)` extensions on `Pkcs1RsaPublicKeyInfo` companion
        * `Pkcs1RsaPrivateKeyInfo`:
            * `Pkcs8PrivateKeyInfo.decodeRsaPrivateKey()` -> `Pkcs1RsaPrivateKeyInfo.of(Pkcs8PrivateKeyInfo)`
            * `Pkcs8PrivateKeyInfo.rsa(...)` -> `Pkcs8PrivateKeyInfo(...)` extensions on `Pkcs1RsaPrivateKeyInfo` companion
        * `Sec1EcPrivateKeyInfo`:
            * `Pkcs8PrivateKeyInfo.decodeEcPrivateKey()` -> `Sec1EcPrivateKeyInfo.of(Pkcs8PrivateKeyInfo)`
            * `Pkcs8PrivateKeyInfo.ec(...)` -> `Pkcs8PrivateKeyInfo(...)` extensions on `Sec1EcPrivateKeyInfo` companion
    * Renamed the `effectiveX` getters on `RsaSsaParams` to `X` getters, and the old `X` getters to `rawX` getters, to better reflect their purpose.
* **Dependency Updates:**
    * Kotlin 2.4.10
    * Bouncy Castle 1.85

## 0.6.1
* **Fixes:**
    * `X509GeneralName.IpAddress` now accepts the RFC 5280 §4.2.1.10 name-constraints encoding (address **plus** subnet mask: 8 octets for IPv4, 32 for IPv6) in addition to bare `subjectAltName`/`issuerAltName` addresses (4/16 octets). It previously rejected the 8/32-octet form outright.
    * `Asn1String.IA5.isValid` now accepts the complete 7-bit IA5 alphabet `0x00`–`0x7F`, **including DELETE (`0x7F`)** (ITU-T T.50 / ISO 646); DELETE was previously rejected.
    * `Asn1String.UTF8.isValid` now reports UTF-8 well-formedness (RFC 3629) via a canonical round-trip instead of testing for the replacement character. A value that legitimately contains U+FFFD is no longer rejected, and malformed/overlong byte sequences are detected reliably.
    * `Asn1String.Teletex`, `Asn1String.General`, and `Asn1String.Graphic` no longer reject legitimate 8-bit or multi-byte content (e.g. Latin-1 or CJK graphic characters). Their true repertoires (ISO 2022 / T.61) cannot be validated exactly, so `isValid` now performs best-effort recognition: `true` for a recognized subset, `null` ("unknown") otherwise, and **never `false`**; their `String` constructors consequently never throw.
        * **API change:** `isValid` on these three types widened from `Boolean` to `Boolean?` (the base-class type; `null` denotes "not validated / unknown").
* **Other Changes:**
    * Document `Asn1String` repertoires and validation semantics — a per-type table, best-effort/limitation warnings, and X.680 §41 / ITU-T T.50 / RFC 3629 references — in the low-level guide and API docs.

## 0.6.0
* **Features:**
    * Add a closed, serializable `X509GeneralName` hierarchy covering every RFC 5280 `GeneralName` alternative.
    * Make X.509 `otherName` extensible through OID-based open polymorphism. Unknown OIDs use a structural fallback by default, while applications can register semantic subtypes on a custom `Der` instance or through the startup-only `DefaultDer` registry.
    * Add `Asn1OpenPolymorphicWithDefaultSerializer`, allowing extensible models to provide a structural serializer that is automatically replaced by contextual open-polymorphism registrations when available.
    * Allow OID-based open-polymorphism configurations containing only a `catchAll` registration.
* **Fixes:**
    * Preserve an enclosing property or inline-wrapper tag when dispatching to an open-polymorphic subtype, without conflating it with tags belonging to the selected subtype's own fields.
* **Other Changes:**
    * Document provided-fallback open-polymorphism fallbacks and extending X.509 `OtherName`, including default-`DER` startup registration with test-backed source snippets.
    * Remove Deprecations
    * Use [Lockhart's Sleight of Hand](https://github.com/jeffdgr8/kotbase/blob/6d783c25bb31be3a374b19d406a8fbd14f149f6f/couchbase-lite/src/appleMain/kotlin/kotbase/Scope.apple.kt#L33-L51) to hide throwing ObjC getters:
        * Allows properly annotating throwing getters in common main sources
    * Remove private fuzzer from public repo

## 0.5.0
* **Fixes:**
    * OID-based open-polymorphism catch-all fallback no longer encodes the discriminator OID twice.
    * `Asn1SetOf` is now persistent across DER round-trips. The raw DER parser automatically emits `Asn1SetOf` when a SET's children all share the same tag; otherwise it falls back to plain `Asn1Set`.
    * Added `Asn1SetOf.commonTag` property for convenient access to the shared tag.
    * `Asn1SequenceOf` is now persistent across DER round-trips. The raw DER parser automatically emits `Asn1SequenceOf` when a SEQUENCE's children all share the same tag; otherwise it falls back to plain `Asn1Sequence`.
    * Added `Asn1SequenceOf.commonTag` property for convenient access to the shared tag.
    * `kxs` now encodes Kotlin unsigned primitive serializers as unsigned ASN.1 INTEGER values instead of falling through to their signed inline backing values.
    * `ByteArrayBuffer.readByteArray` now performs Long-safe bounds checks and no longer risks state corruption from `Int` overflow at large indices.
    * `BitSet`:
        * Fix public byte views leaking preallocated or trailing zero backing bytes
        * Fix `Asn1BitString(BitSet)` encoding of preallocated and sparse bit sets
        * Fix `equals` so comparisons are symmetric and based on logical compact content
        * Add `hashCode` consistent with compact byte equality
        * Fix `BitSet(nBits) { ... }` creating a bogus final bit when the initializer returned `false` for the last index
        * Make `nextSetBit` search compact logical bytes instead of raw backing buffer
    * Deserializing from ByteArray must now consume all bytes; trailing garbage no longer passes silently.
    * Preserve malformed X.509 certificate unique IDs during DER decoding and re-encoding, while exposing strict semantic BIT STRING accessors that still fail lazily on invalid padding.
* **Hardening:**
    * Remove reliance on the runtime throwing on out-of-bounds indexed access (Kotlin/Wasm traps instead of raising a catchable exception): `BitSet.getBit`, `kxs` enum-ordinal mapping, and `DerDecoder` element access now bounds-check explicitly and surface catchable `Asn1Exception`/`SerializationException` on every platform.
    * Rework DER element parsing and encoding toward iterative implementations, reducing stack growth on deeply nested inputs.
    * Enforce stricter length accounting and overflow checks across raw DER parsing, including malformed-length rejection, parent/child length consistency, and `Long`/`Int` conversion guards.
    * Add deep-structure and deep-octet-string regression tests, plus additional edge-case coverage for parser limits, octet-string decapsulation, and length overflows.
    * Tighten INTEGER minimality handling and two's-complement conversions, including large negative values and large varint-backed magnitudes.
    * Tighten `kxs` integer decoding range checks for primitive Kotlin integer targets and add explicit regressions for enum ordinals outside Kotlin's `Int` domain.
    * Keep `Source`-based parsing bounded by explicit caller limits and strengthen buffer growth / cap behaviour around large inputs.
    * `Asn1Integer` negative INTEGER decode/encode no longer detours through quadratic decimal-string round-trips; two's-complement conversion now stays in byte arithmetic.
    * Large ASN.1 varint / OID arc decoding no longer grows work quadratically through repeated `shl`/`or` chains; big unsigned varints are now unpacked in one pass.
    * `BitSet(nBits)` now rejects the exact preallocation overflow boundary instead of wrapping during the final `+ 1` byte-count adjustment.
* **Features:**
    * ASN.1 GENERALIZED TIME now supports arbitrary precision fractional second representation. **This is a breaking change**
        * `Asn1Time` is now a `sealed` class consisting of
            * `SecondsCapped`, trimming fractional seconds (old behaviour)
            * `Fractional`, keeping arbitrary precision fractional seconds (full DER-compliance)
        * `X509TbsCertificate` now takes `SecondsCapped` time as constructor parameters, but still parses `Fractional` time for leniency.
    * `ObjectIdentifier` is now `Comparable<ObjectIdentifier>`
* **Other Changes:**
    * Add a `benchmarks` module with certificate, length, raw-TLV, rendering, resource-corpus, and SET-sorting benchmarks.
    * Extend public docs for low-level parsing and `kxs` behavior, including newer hardening and limit semantics.
    * Add `io` helpers and tests around sink-based rendering / streaming interop.
    * Refactor large parts of low-level DER parsing, IO buffering, and encoder/decoder internals for clearer ownership boundaries and better reuse of checked integer helpers.
    * Add more regression coverage across `core`, `io`, and `kxs` for parser edge cases, nested inputs, integer limits, and rendering/streaming scenarios.

## 0.4.0
* **Fixes:**
    * Asn1Real now properly encodes minimally. REAL encoding is an oddball because hardly any library properly supports it (pyasn1 is the rare exception).
    * BIT STRING decoding now rejects empty content
    * Resolve instantiation deadlock from hell
* **Features:**
    * Asn1Real:
        * Now normalizes and can thus be fed arbitrary mantissas and exponents
        * Now supports negative zero -> deprecate `Asn1Reals.Zero` and replace with `Asn1Real.PositiveZero`
        * Now supports NaN
        * Now optionally supports permissive decoding but will normalise. So re-encoding will not produce the same bytes in this case.
            * Needs to be explicitly toggled on for individual invocations of decoding functions
            * Is NOT exposed via `decodeFromTlv()` and serialization pipelines, but lives on `Asn1Real.decodeFromAsn1ContentBytes()` et al.
* **Hardening:**
    * Fix hard limits on UVarInt / tag number parsing
    * Fix minimality constraints for integer decoding
    * Add an optional `lienient: Boolean` flag to integer number parsing to optionally disregard minimality constraints
* **Dependency Updates:**
    * Kotlin 2.4.0
    * kotlinx.coroutines 1.11.0
* Migrate to matrix testing

## 0.3.1
* **Dependency Updates:**
    * Kotlinx.io 0.9.0
* **Hardening by Fuzzing:**
    * OID
        * now stricter, requiring minimal encoding
        * correctly parses `2` root arc now
    * UNIVERSAL Tag 15 is now rejected
    * ASN.1 NULL semantic parsing now checks for empty content
* **Other Changes:**
    * Make internal Sink adapter inline 

## 0.3.0
* **Features:**
    * Add catch-all fallback to OID-based open-polymorphism
        * Allow defining a fallback-catchall class that has an oid property that is used to when no exact match for an OID is present
        * Example: OID-based extensions modelled as an open base class and some concrete subclasses with fixed OIDs:
            * If a matching subclass OID is encountered, deserialise to that subtype, if not: fallback to open base class and assign encountered OID to the oid property of the base class
    * Asn1Integer now has `toInt()` and `toIntOrNull()` 
    * `ExplicitlyTagged<T>` can now be used as a property delegate
    * `BitSet`
        * new `copyOf()` function that returns a new deep-copied `BitSet` with the same content as the original
        * new `nextSetBitAfter(index)` function for exclusive "next bit after this index" searches
        * Is now directly serializable also from/to ASN.1 as `Asn1BitString`
* **Fixes:**
    * Deserializing from ByteArray must consume all bytes now, otherwise it will throw. This is how it should have always been.
    * X.509 General Names parsing 
    * Fix value/inline class handling
        * Fix raw Asn1Element deserialzation bug where tag overrides would causes errors instead of correct conversions
        * Fix silent truncation of `Byte`/`UByte` and `Short`/`UShort` when deserializing, but throw instead
    * `BitSet`:
        * Fix public byte views leaking preallocated or trailing zero backing bytes
        * Fix `Asn1BitString(BitSet)` encoding of preallocated and sparse bit sets
        * Fix `equals` so comparisons are symmetric and based on logical compact content
        * Add `hashCode` consistent with compact byte equality
        * Fix `BitSet(nBits) { ... }` creating a bogus final bit when the initializer returned `false` for the last index
        * Make `nextSetBit` search compact logical bytes instead of raw backing buffer
    * Preserve malformed X.509 certificate unique IDs during DER decoding and re-encoding, while exposing strict `Asn1BitString` semantic getters that throw lazily on invalid padding
* Hardening:
    * Reject UNIVERSAL zero tagged asn.1 elements
    * Fail hard for unterminated ASN.1 varints even below the maximum number of bytes to decode
    * Enforce specifying a limit on the maximum number of bytes to be read from a `Source`
    * Harden against malformed length encodings and children longer than the parent
        * Virtually all of these are just short-circuits to fail fast, before other checks would have kicked in
    * Enforce stricter padding validity checks for BIT STRING
        * Padding bits must be zeroed out
        * If padding is present, at least one byte of data must be present
        * ByteArrays to be serialized as BIT STRING using `@Asn1BitString` annotation now enforce zero padding bits on deserialization
    * Add tests for `BitSet` compaction, equality/hash behaviour, `Asn1BitString(BitSet)` edge cases, initializer behaviour, and inclusive/exclusive next-set-bit boundaries
    * Tighten raw ASN.1 BOOLEAN to strict `0x00` / `0xFF` and manually relax in compound usages
        * X509CertificateExtension now carries raw bytes to keep malformed inputs, but sanitizes eagerly
* **Other Changes:**
    * `BitSet`:
        * Clarify `nextSetBit` docs: search starts inclusively from `fromIndex`
        * Clarify `forEachIndexed`
        * Now serializes like `Asn1BitString` (and not as binary string any more) and can thus be used interoperably in serializable ASN.1 structures (but not `Asn1Encodable`s)
    * Core renames:
        * `Asn1TagClass` -> `Asn1Tag.Class`
        * `Asn1TagConstructedBit` -> `Asn1Tag.ConstructedBit`
        * `Asn1ElementStringSerializer` -> `Asn1ElementFallbackBase64Serializer` (you should never have used this, aynways!)
        * `Asn1BitStringSerializer` -> `Asn1BitStringComponentSerializer`
    * **Massively refactor `crypto` classes**:
        * Everything's now based on kotlinx.serialization (`kxs` module)
        * Add RSA PSS Param class and helper parsing functions
        * TbsCertificate and Pkcs10CertificationRequestInfo now have `rawVersion` and (semantic) version as per X.509/PKCS#10:
            * raw version is an ASN.1 Integer and corresponds to the encoded value
            * (semantic) version is a Kotlin `Int` and is raw version plus 1
        * Tighter alignment with X.509, PKCS#10 and co:
            * production crypto/PKI types are now regular `@Serializable` data/value classes instead of companion-driven manual `Asn1Serializable` / `Asn1Encodable` model implementations
            * `X509AlgorithmIdentifier` is now a dedicated public type and is used consistently across certificate / CSR / key-container models instead of raw ASN.1 sequence stand-ins
            * several fields were tightened to more spec-shaped public types, e.g. EC optional fields now use explicit-tag wrappers and encrypted private-key algorithm/data fields now use `X509AlgorithmIdentifier` / ASN.1 octet-string types instead of generic `Asn1Element`
        * X509TbsCertificate now only accepts integer serial numbers
        * Refactor to use new explicit tag delegates, so crypto classes now expose unwrapped values
        * Rename `RelativeDistinguishedName` -> `X500RelativeDistinguishedName`
        * Rename `AttributeTypeAndValue` -> `X500AttributeTypeAndValue`
        * Rename `SignatureAlgorithmIdentifier` -> `X509AlgorithmIdentifier`
        * Rename `TbsCertificate` -> `X509TbsCertificate`
        * Rename `RsaPrivateKeyInfo` -> `Pkcs1RsaPrivateKeyInfo`
        * Rename `RsaOtherPrimeInfo` -> `Pkcs1RsaOtherPrimeInfo`
        * Rename `RsaPublicKeyInfo` -> `Pkcs1RsaPublicKeyInfo`
        * Rename `EcPrivateKeyInfo` -> `Sec1EcPrivateKeyInfo`
        * Rename `Attribute` -> `Pkcs10CsrAttribute`
        * Rename `Pkcs10CsrAttribute.X509CertificateExtension` -> `Pkcs10CsrAttribute.ExtensionRequest` <!-- forgot to rename in previous PR-->
    * Drop deprecated Apple X64 targets
    * Rework PEM parsing to be far more usable in practice
* Dependency Updates:
    * Kotlin 2.3.21
    * Serialization 1.11.0

## 0.2.1
Equivalent to 0.2.0 but maven central is more brittle than ever, so publishing 0.2.0 went south.

## 0.2.0
* Rework Signatures to a single class encoding from/to BIT STRING
* Make cert and CSR actually use the new signature class 
* DER registry was thinned out and now only lives in `kxs` module. It is now called `DefaultDer`
* make `PemBlock` also `PemEncodable`
* validate PEM labels when decoding ASN.1 PEM blocks
* disallow PEM headers by default when decoding ASN.1 PEM blocks; implementing classes can override this
* normalize function naming surrounding PEM:
  * `T.encodeToPem` and `T.Companion.decodeFromPem` for `String` <-> `T`
  * `T.encodeAllToPem` and `T.Companion.decodeAllFromPem` for `String` <-> `Iterable<T>`
  * `T` can be `PemBlock`, or any other `PemEncodable` (whose companion is `PemDecodable`)
* move a bunch of internals to an internal-utils module to avoid polluting the global namespace
* Normalize `GeneralNameImplicitTags` capitalization

## 0.1

### 0.1.1

* More compliant SBOMs

### 0.1.0

* Initial release outside Signum
* Fixed `kxs` implicit-tag decoding for ASN.1 wrapper types, including `Asn1Time`/`kotlin.time.Instant` handling and pre-1950 vs post-2050 time format selection
* Fixed ASN.1 REAL encoding for subnormal floating-point values, which could previously round-trip certain `Double`s to half their value
* Fixes SET children sorting
* Fixed Tag Sorting
