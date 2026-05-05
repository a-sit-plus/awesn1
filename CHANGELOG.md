# Changelog

## NEXT
* Drop deprecated Apple X64 targets
* Add catch-all fallback to OID-based open-polymorphism
    * Allow defining a fallback-catchall class that has an oid property that is used to when no exact match for an OID is present
    * Example: OID-based extensions modelled as an open base class and some concrete subclasses with fixed OIDs:
        * If a matching subclass OID is encountered, deserialise to that subtype, of not: fallback to open base class and assigne encountered OID to the oid property of tha base class
* Fix value/inline class handling
* Asn1Integer now has `toInt()` and `toIntOrNull()`
* `ExplicitlyTagged<T>` can now be used as a property delegate
* Tighten raw ASN.1 BOOLEAN to strict `0x00` / `0xFF` and manually relax in compound usages
    * X509CertificateExtension now carries raw bytes to keep malformed inputs, but sanitizes eagerly 
* Fix silent truncation of `Byte`/`UByte` and `Short`/`UShort` when deserializing, but throw instead
* Core renames:
    * `Asn1TagClass` -> `Asn1Tag.Class`
    * `Asn1TagConstructedBit` -> `Asn1Tag.ConstructedBit`
    * `Asn1ElementStringSerializer` -> `Asn1ElementFallbackBase64Serializer` (you should never have used this, aynways!)
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
    * Add `Versioned` interface
    * Refactor to use new explicit tag delegates, so crypto classes now expose unwrapped values
    * Rename `RelativeDistinguishedName` -> `X500RelativeDistinguishedName`
    * Rename `AttributeTypeAndValue` -> `X500AttributeTypeAndValue`
    * Rename `SignatureAlgorithmIdentifier` -> `X509AlgorithmIdentifier`
    * Rename `TbsCertificate` -> `X509TbsCertificate`
    * Rename `RsaPrivateKeyInfo` -> `Pkcs1RsaPrivateKeyInfo`
    * Rename `RsaOtherPrimeInfo` -> `Pkcs1RsaOtherPrimeInfo`
    * Rename `EcPrivateKeyInfo` -> `Sec1EcPrivateKeyInfo`
    * Rename `Attribute` -> `Pkcs10CsrAttribute`
    * Rename `Attribute` -> `Pkcs10CsrAttribute`
    * Rename `RsaPublicKeyInfo` -> `Pkcs1RsaPublicKeyInfo`

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
