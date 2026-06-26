---
hide:
- navigation
---

# Hardening, Fuzzing & Robustness

awesn1 has a parser at its core. Parsers parse data from untrusted (attacker-controlled) input. Hence, the awesn1 raw parser, encoder, and
renderers are designed to **fail predictably** on adversarial input: a malformed, oversized, or deeply-nested blob
yields a bounded `Asn1Exception`/`SerializationException` or a bounded result — never a `StackOverflowError`, runaway
recursion, an uncatchable crash, or silent corruption.

This page collects the robustness model in one place. For the APIs it refers to, see the
[Low-Level ASN.1 API](lowlevel.md) and the [Serialization](kxs.md) pages.

!!! warning "Hardening is an ongoing effort — and never truly *done*"

    Hardening a parser of attacker-controlled input is a moving target: Treat the guarantees on this page as a living baseline, not a finished checklist.
    We keep extending the fuzzing and coverage behind them, improve things and fix issues as we discover them.

    **If you find a gap, please report it confidentially.** Follow our
    [security policy](https://github.com/a-sit-plus/awesn1/blob/main/SECURITY.md): Do **not** open a public issue if you discover a potential security vulnerability.
    Use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/privately-reporting-a-security-vulnerability)
    instead. We will acknowledge it promptly and do our best to push out a fix as soon as possible.

## Recap: Deferred Semantic Parsing

awesn1 separates *raw DER parsing* from *ASN.1 meaning* (see
[Deferred Semantic Parsing](lowlevel.md#deferred-semantic-parsing)):

- The **raw parser** enforces only what keeps the tree well-bounded and DER-shaped: it rejects indefinite-length
  encoding, non-minimal long-form lengths, length overflow, children that overrun their parent, high-tag-number form
  for tags that belong in low-tag form (`≤ 30`), and universal tags `0` (end-of-contents) and `15`.
- **Semantic validation is deferred** to typed decoders (`decodeToBoolean`, `Asn1Integer.decodeFromAsn1ContentBytes`,
  string/time/OID decoders, …). This is deliberate: it lets you parse quirky real-world input into a raw tree, preserve
  exact bytes for diagnostics or signature verification, and *then* decide how strict to be.

Deferred semantics is a **design decision, not a gap** — but every semantic decoder is still held to the robustness
guarantees below (no leak, no amplification, no overflow).

## Hardening Scope
This section describes which parts of awesn1 are hardened against hostile input and to what extent.


### Purely Iterative Parsing and Encoding (New since 0.5.0)

Parsing, encoding (`derEncoded`/`encodeTo`), `prettyPrint`/`toString`, `equals`/`hashCode`, and SET ordering are all
**iterative**, using explicit work-stacks instead of the call stack. OID decoding/encoding and
big-integer arc arithmetics are loop-based as well. Arbitrarily deep nesting — `SEQUENCE` in `SEQUENCE`, `EXPLICIT` tags,
custom constructed structures, encapsulating `OCTET STRING`s — cannot exhaust the stack. Encapsulating octet strings are
decapsulated iteratively and without per-layer byte copies, so nested octet string content stays linear in input size.

### Bounded Lengths and Overflow Guards

- Every element exposes `contentLength: Int` / `overallLength: Int`, **guarded**: an aggregate size exceeding
  `Int.MAX_VALUE` (~2 GiB) throws `Asn1Exception` rather than silently wrapping. The `…Long` accessors and
  `encodeTo(sink)` exist for callers who deliberately work past 2 GiB and/or require streaming output.  
  **Do note that some buffering still occurs**, but it will only ever be linear.
- A single primitive's content is `ByteArray`-backed, so it is hard-capped at `Int.MAX_VALUE` bytes; a longer primitive
  is rejected, not truncated.
- All length sums go through `plusExact`, and every attacker-influenced `Long`→`Int` narrowing goes through
  `toIntChecked` — so a size computation can never quietly turn a bounds check into a bypass.

By default everything stays `Int`-based: `DerConfiguration.maxInputLength` defaults to `Int.MAX_VALUE`, so any input
decoded with the defaults produces only `Int`-sized lengths and never trips the guards — the `…Long` accessors and
`encodeTo(sink)` are only relevant once you deliberately raise that limit to work with multi-gigabyte structures.

### Catchable Errors Only

Every failure on hostile input surfaces as a catchable `Asn1Exception` (core), `SerializationException` (kxs), `NumberFormatException`, `IllegalArgumentException`,
but never a fatal VM error, *unless you forgt to bound your inputs*, in which case you can still run out of memory.
Decode/parse paths run inside `runRethrowing`/`runWrappingAs`, which catch non-fatal `Throwable`s and wrap them; only VM-fatal errors are rethrown.

### Bounded Depth and Collection Sizes

- `kxs` shares a `DerDepthGuard` between `DerDecoder`/`DerEncoder` that throws `SerializationException` past
  `DerConfiguration.maxNestingDepth` (default **128**). This means that if you ever expect more than 128 levels of
  nesting in user-controlled input, **increase this cap**.
- A `MAX_COLLECTION_SIZE` guard (`Int.MAX_VALUE - 8`, checked per append) turns an overfull child list into a catchable
  `Asn1Exception`. This is an addressability backstop, **not** a heap-DoS defense — see input bounding below.

### Bounded Rendering

`toString()` and `prettyPrint()` are length-capped (JVM `String`/`StringBuilder` are themselves `Int`-bounded) and
**truncate** with a `… (output truncated)` marker rather than exhausting memory; an oversized primitive's content is
shown as a bounded hex prefix with a `…(N bytes)` note. These renderers are for human inspection — use `derEncoded` for
the exact bytes.

### No Reliance on Implicit Array Bounds Checks (Kotlin/Wasm)

On JVM/Native, an out-of-bounds array access throws a catchable exception; on Kotlin/Wasm it **traps** instead. awesn1
therefore does not depend on the runtime to throw on out-of-range indexing during parse and encode.
Hot paths bounds-check explicitly (e.g. `BitSet.getBit`, the `kxs` enum-ordinal mapping, and `DerDecoder` element access),
s.t. that the behaviour is identical on all targers and errors stay catchable.

### Fail-Fast Ambiguity Detection (kxs)

`kxs` rejects ambiguous DER layouts at **encode time** rather than emitting bytes that decode differently elsewhere
(adjacent optional fields sharing a leading tag, undecidable null-omission, ambiguous inline-class tagging). There is no
`ignoreUnknownElements`: trailing or unexpected elements are rejected. See [Deep Dive: Disambiguation](kxs.md#deep-dive-disambiguation).

## Fuzzing and Regression Coverage

The robustness guarantees are backed by an extensive test surface containing targeted hostile inputs and the [OpenSSL fuzz corpora](https://github.com/openssl/fuzz-corpora)
run through a third-party classifier/oracle, whose behaviour is then compared with awesn1's.
The test harness includes:

- **Structural limits:** deep structural nesting (tens of thousands of levels), deep OCTET STRING decapsulation,
  length parsing/overflow guards, parent/child length-consistency enforcement, tag parsing edge cases, and bounded
  `Source` enforcement.
- **Numeric edge cases:** INTEGER minimality and two's-complement conversion (incl. large negatives and large
  varint-backed magnitudes), OID arc decoding, `BitSet` and BIT STRING edge cases.
- Signed/Unsigned integer to primitive mapping for `kxs`, ensuring that numbers round-trip byte-for-byte.
- **Differential / corpus fuzzing:** randomized and corpus-driven inputs (including a real-world certificate corpus)
  parsed and round-tripped, asserting that malformed input fails with a bounded exception and that valid input
  round-trips byte-for-byte.
- A humungous unit test suite using data-driven testing and property testing, with actual test data series in the millions,
  used to ensure correct round-tripping and accurate semantics based comparing with outside, known-good implementations.

## Input-Bounding as the Caller's Responsibility

!!! danger "Always Bound Untrusted Input"

    awesn1 parses into an in-memory tree, so **input size directly bounds memory**, and the library does **not** impose
    a small default below `Int.MAX_VALUE`. **Hence, wherever denial-of-service is a concern, you must cap input yourself:**
    
    - **`ByteArray`** parsing is bounded by the array's size — sanity-check that size before parsing untrusted data.
      Even a small blob of tiny nested elements can allocate a large object graph (but never causes a stack overflow).
    - **`Source`** (streaming) parsing takes a byte `limit` as a **mandatory** parameter; there is no unbounded
      streaming overload.
    - Via `kotlinx.serialization`, the cap is `DER { maxInputLength = … }` (default `Int.MAX_VALUE`); lower it for
      untrusted decode.

It is a deliberate decision to leave input bounding to the caller. Only the caller knows realistic, expected input's sizes and
semantics. Take X.509 certificates as an example: ECDSA-signed certificates are usually small, issuer DNs are also usually bounded,
but PQC-signed certificates may even exceed certificates signed with long RSA keys.
Also, when parsing CMS or CRLs, the expected input sizes are orders of magnitude larger compared to parsing certificates.

**Hence, callers must bound the input size themselves!**

### Memory Amplification — Deep Nesting as Worst Case

A parsed tree is an in-memory object graph several times larger than the DER bytes it came from, and **deeply nested
structures amplify the most**. A real-world certificate/attestation corpus parses at roughly **24×** its DER size as a
raw `Asn1Element` tree (see [Low-Level → Memory](lowlevel.md#memory)). A *degenerate* chain of nested empty structures
is far worse per input byte: a tree of **50 000** single-child empty `SEQUENCE`s — only a few bytes per level on the
wire — materialises to about **9 MiB** of heap, i.e. roughly **190 bytes per nesting level** (one structure object, its
child list, and the list's backing array).

The iterative parser guarantees this never *crashes* the stack — but the heap cost still grows with input. This
is precisely why input bounding is mandatory: a small but pathologically nested blob can still exhaust memory, and 
worst-case amplification far above the ~24× of normal input means your byte cap must be chosen with the *amplified*
in-memory size in mind, not just the wire size.

### Constructing Huge Data Programmatically

These guarantees concern *parsing untrusted input*. If you build an `Asn1Element` tree in code whose aggregate size
exceeds `Int.MAX_VALUE`, that is under your control: read the `…Long` accessors and encode via `encodeTo(sink)` to a
streaming sink instead of materializing `derEncoded` (a single `ByteArray`, itself capped at ~2 GiB).

## Residual Risks

What cannot be hardened due to `kotlinx.serialization` intrinsics: 

The `kxs` module implements a `kotlinx.serialization` format. Some sharp edges are inherent to that framework's
contract and **cannot** be closed from inside awesn1. Be aware of them when using `kxs`:

- **Recursive `@Serializable` types and open polymorphism recurse on the call stack.** `kotlinx.serialization` drives
  decoding by invoking each type's generated `deserialize`, so a self-referential type (`data class Rec(val child: Rec?
  = null)`) or a deeply nested open-polymorphic hierarchy recurses on the stack – even though awesn1's own raw parser is iterative and never overflows.
  This is why `kxs` bounds this framework recursion with `DerConfiguration.maxNestingDepth` (default **128**), throwing a catchable
  `SerializationException` long before the stack is exhausted. But the recursion lives in framework-generated code that
  awesn1 cannot influence, so the guard is your only protection: **raising `maxNestingDepth` toward the thousands
  re-opens the `StackOverflowError`.** Keep it as low as your schema genuinely requires, and never raise it to
  accommodate attacker-influenced depth.

- **Pre-parsed `Asn1Element` trees bypass `maxInputLength`.** `maxInputLength` and the streaming byte `limit` bound the
  *parse* step. If you parse a tree yourself (or via the low-level API) and hand the already-materialized
  `Asn1Element` to `DER`/`decodeFromTlv`, the allocation already happened — the cap can no longer protect you. Bound
  the bytes *before* you build the tree.

- **Custom `KSerializer`s drive the codec directly.** A hand-written serializer has full control over the sequence of
  `encode*`/`decode*`/`beginStructure` calls. `kxs` detects and rejects *recognizable* ambiguity at encode time, but it
  cannot stop a custom serializer from emitting structurally valid yet semantically wrong (or non-canonical) DER, or
  from driving the decoder in an order its descriptor does not describe. Custom serializers are trusted code — review
  them as such. See [Custom Serializers Re-Introducing Ambiguity](kxs.md#custom-serializers-re-introducing-ambiguity).

- **The `@Serializable` descriptor is the only schema source.** `kotlinx.serialization` exposes a structural descriptor,
  not your runtime invariants. `kxs` cannot enforce constraints the descriptor cannot express — value ranges beyond the
  Kotlin type, cross-field relationships, or "this `Int` is really a constrained enumerated" — so validate those in
  your own code after decoding, or implement custom serializers on top.

- **Inline value classes are flattened by the framework.** `kotlinx.serialization` erases single-field inline
  (`value`) classes to their backing value before `kxs` sees them. Placing an ASN.1 tag on an inline class's backing
  property is therefore ambiguous; `kxs` fails fast with a `SerializationException` rather than guessing, but it cannot
  make that combination *work*. See [Inline/Value Classes](kxs.md#inlinevalue-classes).

- **Absent vs. null vs. default is not always expressible.** The framework's `decodeElementIndex` protocol cannot, on
  its own, distinguish an omitted optional field from an explicit null or a default for adjacent fields that share a
  leading tag. `kxs` makes this decidable by rejecting undecidable layouts at encode time and requiring explicit
  disambiguation (implicit/EXPLICIT tags or leading-tag metadata), but it cannot retrofit a fundamentally ambiguous
  schema — you must disambiguate it. See [Deep Dive: Disambiguation](kxs.md#deep-dive-disambiguation).

## See also

- [Low-Level ASN.1 API](lowlevel.md) and its [Performance](lowlevel.md#performance) numbers
- [Serialization → Deep Dive: Disambiguation](kxs.md#deep-dive-disambiguation)
