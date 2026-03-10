# PEM Module Development Notes

## Regenerating OpenSSL Fixtures

The PEM fixture corpus is generated with `openssl` and stored in:

`core/src/jvmTest/resources/fixtures/openssl`

Run:

```bash
./core/scripts/regenerate-openssl-fixtures.sh
```

Then validate:

```bash
./gradlew :core:jvmTest
```

## Fixture Intent

- Covers both encrypted PEM styles:
  - legacy header-based encryption (`Proc-Type`, `DEK-Info`)
  - PKCS#8 encrypted keys (`ENCRYPTED PRIVATE KEY`)
- Includes multi-block documents and mixed-label bundles.
- Exact bytes may change across regenerations; tests assert parser behavior and round-trip invariants.
