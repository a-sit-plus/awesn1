# Changelog

## NEXT
* Drop deprecated Apple X64 targets
* Add catch-all fallback to OID-based open-polymorphism
    * Allow defining a fallback-catchall class that has an oid property that is used to when no exact match for an OID is present
    * Example: OID-based extensions modelled as an open base class and some concrete subclasses with fixed OIDs:
        * If a matching subclass OID is encountered, deserialise to that subtype, of not: fallback to open base class and assigne encountered OID to the oid property of tha base class
* Fix value/inline class handling
* **Massively refactor `crypto` classes**:
    * Everything's now based on kotlinx.serialization (`kxs` module)
    * tighter alignment with X.509, PKCS#10 and co:
        * production crypto/PKI types are now regular `@Serializable` data/value classes instead of companion-driven manual `Asn1Serializable` / `Asn1Encodable` model implementations
        * `AlgorithmIdentifier` is now a dedicated public type and is used consistently across certificate / CSR / key-container models instead of raw ASN.1 sequence stand-ins
        * several fields were tightened to more spec-shaped public types, e.g. EC optional fields now use explicit-tag wrappers and encrypted private-key algorithm/data fields now use `AlgorithmIdentifier` / ASN.1 octet-string types instead of generic `Asn1Element`

## 0.2.1
Equivalent to 0.2.0 but maven central is more brittle than ever so publishing 0.2.0 went south.

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
