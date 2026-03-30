# Changelog

## NEXT
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

## 0.1

### 0.1.1

* More compliant SBOMs

### 0.1.0

* Initial release outside Signum
* Fixed `kxs` implicit-tag decoding for ASN.1 wrapper types, including `Asn1Time`/`kotlin.time.Instant` handling and pre-1950 vs post-2050 time format selection
* Fixed ASN.1 REAL encoding for subnormal floating-point values, which could previously round-trip certain `Double`s to half their value
* Fixes SET children sorting
* Fixed Tag Sorting
