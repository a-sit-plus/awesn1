# Changelog

## 0.2

### NEXT

* make `PemBlock` also `PemEncodable`
* normalize function naming surrounding PEM:
  * `T.encodeToPem` and `T.Companion.decodeFromPem` for `String` <-> `T`
  * `T.encodeAllToPem` and `T.Companion.decodeAllFromPem` for `String` <-> `Iterable<T>`
  * `T` can be `PemBlock`, or any other `PemEncodable` (whose companion is `PemDecodable`)
* make a bunch of things `internal` to avoid polluting the global namespace

## 0.1

### 0.1.1

* More compliant SBOMs

### 0.1.0

* Initial release outside Signum
* Fixed `kxs` implicit-tag decoding for ASN.1 wrapper types, including `Asn1Time`/`kotlin.time.Instant` handling and pre-1950 vs post-2050 time format selection
* Fixed ASN.1 REAL encoding for subnormal floating-point values, which could previously round-trip certain `Double`s to half their value
* Fixes SET children sorting
* Fixed Tag Sorting
