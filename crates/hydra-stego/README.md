# hydra-stego

`hydra-stego` converts opaque encrypted bytes into reversible text carriers
and recovers the exact bytes. It provides a zero-model deterministic profile,
slow probability-weighted arithmetic coding, a high-capacity fast Unicode
profile, and a fixed-inference hybrid prose profile. There is no silent
plaintext fallback.

Encryption, authentication, replay handling, and session sequencing remain in
`hydra-msg`. For cover mode, use `Hydra::send_compact` before `Stego::encode`
and `Hydra::receive_compact` after `Stego::decode`. The compact envelope uses HYDRA's
normal ratchet and AEAD but intentionally trades fixed-size padding for a much
smaller input to this high-expansion carrier.

## Navigation

- [Main README](../../README.md)
- [How HYDRA messaging works](../../docs/impl/message-flow/README.md)
- [Spec docs and repo structure](../../docs/spec/README.md)
- [Crates](../README.md)
- [Examples](../../examples/README.md)
- [Public developer API](../../docs/spec/public-developer-api.md)
- [Benchmark notes](../../docs/validation/benchmarks/benchmark-results.md)
- [LAN browser demo](../../examples/stego_lan_chat/README.md)
- [Carrier examples](../../docs/impl/carrier-examples.md)
## Small Rust example

```rust
use hydra_stego::{Stego, StegoError, StegoProfile};

fn round_trip(encrypted_compact_envelope: &[u8]) -> Result<Vec<u8>, StegoError> {
    let stego = Stego::new();
    let cover = stego.encode(encrypted_compact_envelope, StegoProfile::Deterministic)?;
    stego.decode(&cover, StegoProfile::Deterministic)
}
```

The crate root intentionally exposes only `Stego`, `StegoProfile`, and
`StegoError`. Applications that provide an AI backend use the advanced
`hydra_stego::model` module. `ModelConfig` requires an exact runtime/model
fingerprint, and the native `ProcessLanguageModel` adapter additionally
requires an immutable 40-hex model revision and enforces startup/request
timeouts.

## Instant deterministic machine-status mode

`StegoProfile::Deterministic` is a pure Rust profile with no model, tokenizer, Python
runtime, download, or inference. The first record carries 24-28 framed bits;
later records carry 29-33 bits, depending on whether the selected event family
carries a data-bearing detail field. It combines these mechanisms:

1. every physical line is logfmt, but the stream uses four stable event-family
   schemas instead of one rigid row: build records, compact metric samples,
   deployment records, and longer diagnostic/trace records. Each family keeps
   a consistent internal key order while the field count varies naturally;
2. every record begins with a surface-only Unix `ts=` value at microsecond
   precision. The first value is anchored to generation time and later records
   advance monotonically with bounded per-record jitter. Timestamp digits do
   not carry payload bits and the decoder ignores them;
3. `actor`, `context`, `action`, qualifier, and topic vocabularies are selected
   from the current event family. Build records therefore stay with
   runner/builder and build-pipeline concepts, metric records with
   exporter/monitor telemetry concepts, deploy records with controller/deployer
   rollout concepts, and traces with checker/agent diagnostic concepts; and
4. execution style is encoded in a separate `mode` slot while operations stay
   base-form machine verbs. Split-infinitive constructions such as
   `to currently ...`, passive modal chains such as `is expected to ...`, and
   conversational justification tails are absent by construction.

The four schema families each expose four fixed event/kind variants, preserving
a 16-way template choice without random delimiter drift. Build and trace
families carry a technical evidence/scope `detail`; compact metric and deploy
families omit that slot, producing the 24-28 / 29-33 bit capacity range. The
first record fixes one family-appropriate actor and context without spending
those continuation bits; later records spend one actor bit and four context
bits. The low control bits also advance a small state machine that rotates
within each family-specific vocabulary rather than sampling a flat Cartesian
product.

Numeric surface variation is deliberately non-data-bearing. Progress phrases
receive a fresh bounded percentage, metric samples receive fresh bounded
numeric values, and technical identifiers are attached intermittently rather
than to every noun. Context identifiers are likewise optional. Replacing only
those digits does not affect payload recovery.

The deterministic vocabulary is deliberately technical-only. Personal/social
entities such as coffee venues, calendars, guest lists, travel, or dining do
not appear in this profile, and neither do `the team` / `we` / `they` or casual
chat forms such as `gonna`/`wanna`.

Encoding and decoding are linear-time table operations. The decoder ignores
ASCII case, punctuation, whitespace, and non-data-bearing numeric surface
values. The exact cover string can therefore differ across repeated hides of
the same payload even though payload recovery remains deterministic. It does
not survive data-bearing word replacement, insertion, deletion, reordering,
translation, autocorrect, or paraphrasing. Because the event schemas and word
tables are public and encrypted inputs choose branches nearly uniformly, a
motivated observer can still fingerprint their distribution. The carrier also
expands substantially and reveals the framed ciphertext length.

That expansion is an information-capacity boundary, not a grammar bug. The
public stego frame adds 17 bytes. An `N`-byte encrypted HYDRA envelope therefore
needs a first record carrying 24-28 bits and later records carrying 29-33 bits,
depending on whether the selected family carries a data-bearing detail. For
example, the theoretical capacity bounds for a 262-byte envelope remain 68-78
records. This profile is consequently a better contextual fit for mixed
CI/build/metrics/deployment telemetry than for a short one-to-one chat reply.

## Fast Unicode mode

`StegoProfile::FastUnicode` always samples 16 visible model tokens, then appends
an invisible U+2063 separator and a framed byte layer using the 256 Unicode
variation selectors. It therefore performs a constant number of model
inferences whether the HYDRA envelope contains a short message or a large
paragraph. Decoding extracts the selectors without model inference, validates
the stego frame, and returns bytes that must still pass
`Hydra::receive_compact` authentication.

This is an explicit speed-for-concealment tradeoff. The selector run is easy to
detect programmatically, leaks encrypted length, and can be removed by Unicode
normalization, editors, messaging platforms, or copy/paste paths. Use it only
on exact-text transports after testing that they preserve U+2063, U+FE00–
U+FE0F, and U+E0100–U+E01EF.

## Fast hybrid prose mode

`StegoProfile::FastHybrid` performs the same fixed 16 model-token
selections to establish a conversational topic and style. It then carries
framed encrypted bits through a varied grammar: the selected sentence shape
and ordinary opener, manner, action, topic, place, connector, and tone words
each encode part of the frame. There is no appended byte list, delimiter, or
invisible Unicode. Decoding does not run the model, so model latency remains
independent of payload size.

The decoder ignores ASCII letter case, punctuation, and whitespace, making the
profile suitable for transports that normalize those surface details. It does
not survive word replacement, deletion, reordering, autocorrect, translation,
or paraphrasing. Its handcrafted grammar, repeated topic, unusual length, and
uniform encrypted choices can still be recognized by statistical or learned
steganalysis. It is an interactive engineering tradeoff, not a claim of
undetectability.

## Arithmetic mode

At each generated position, the codec:

1. asks the deterministic model for its top candidate IDs and logits;
2. temperature-scales those logits and quantizes their probability mass into
   a 32,768-count integer frequency table, giving every candidate a nonzero
   interval;
3. arithmetic-decodes framed encrypted bits into one candidate; and
4. mirrors the choice through an arithmetic encoder so generation stops only
   after every frame bit is forced by the selected token intervals.

The receiver repeats the candidate calculations and arithmetic-encodes the
observed token choices. A length-delimited frame with an accidental-corruption
checksum tells it where the encrypted envelope ends; deterministic
highest-ranked candidates then make a bounded best effort to finish the
sentence. Candidate counts do not need to be powers of two.

The frame checksum is not a MAC. Recovered data is safe to accept only after
`Hydra::receive_compact` authenticates it.

## Model synchronization

Sender and receiver must agree on all of the following:

- exact model weights and tokenizer files;
- runtime/library versions, device, numeric type, and deterministic settings;
- prompt, candidate filter, candidate count, temperature, and arithmetic
  quantization rules; and
- the exact cover-text bytes.

The demo avoids cross-device floating-point drift by running one shared model
process on the LAN host for both browsers. Independent hosts should compare the
reported content fingerprint and still run interoperability tests on their
actual hardware. A matching file fingerprint alone does not prove numerically
identical inference on different accelerators.

## Security status

| Property | Status |
|---|---|
| Confidentiality, integrity, forward ratchet, replay handling | Supplied by the compact HYDRA envelope, not by arithmetic coding. |
| Probability matching | Implemented against the model's top-N distribution after specified temperature scaling and integer quantization. |
| Deterministic-prose detectability | Material. Four stable logfmt event-family schemas, surface-only monotonic timestamps, family-correlated actor/context/action pools, action-centric base verbs, and intermittent randomized numeric values remove the identified rigid-schema, missing-time, flat-co-occurrence, split-infinitive, passive-modal, and domain-pollution artifacts. The public CFG, schema family frequencies, vocabulary, transition statistics, and expansion remain fingerprintable. |
| Fast Unicode detectability | High. Its default-ignorable separator and variation-selector suffix are directly recognizable to a code-point-aware observer. |
| Fast hybrid-prose detectability | Material. It removes the explicit word list, but its public handcrafted grammar, repeated topic, length, and encrypted choice distribution remain distinguishable from ordinary conversation. |
| Formal undetectability | Not claimed. Truncation, filtering, finite precision, framing, model artifacts, and generated-text quality can all be detectable. |
| Secret stego key / deniability | None. The current arithmetic transform is public and the frame is recognizable to a codec-aware observer. |
| Edit or paraphrase resistance | Surface-only for the deterministic and hybrid profiles: ASCII case, punctuation, and whitespace may change. Autocorrect, translation, deletion, word replacement, or paraphrasing can break decoding. |
| Length/timing resistance | None. Compact HYDRA and the cover length leak size; endpoints, timing, and the choice of cover mode remain observable. |
| Model synchronization | Enforced by a fingerprint contract; the demo hashes the local snapshot and shares one inference process. Cross-host numeric equivalence is still an operator responsibility. |
| Resource bounds | Payload, raw-cover, word/token, framed-selector, model request/response, timeout, and compact-envelope limits are explicit. Model downloads and inference remain expensive. |

## What the Rust integration independently hardens

The upstream warning does not enumerate a canonical bug list, and several of
these safeguards also exist in newer revisions of the referenced project. This
integration independently covers the following engineering failure modes:

- arithmetic termination is self-delimiting and round-trip tested across
  biased, non-power-of-two candidate sets;
- generated text must tokenize back to the exact selected IDs;
- candidate IDs, scores, duplicates, limits, and model fingerprints are
  validated;
- every decode path enforces a raw carrier ceiling before unbounded
  tokenization/word collection, with profile-specific framed/token/word caps;
- the native model subprocess has bounded request/response sizes, absolute
  startup/inference deadlines across writes and reads, and fail-closed child termination;
- the demo uses one persistent local model with incremental KV-cache reuse;
- model files are content-hashed by the bundled backend;
- encrypted compact envelopes retain HYDRA authentication, ratcheting, replay
  rejection, and safe out-of-order delivery; and
- the browser exposes explicit model choices, resource estimates, and a
  hardware-informed recommendation.

Those are meaningful safeguards, but they do not solve the research-level
weaknesses. The remaining gaps are not caused by Go, Rust, or the original
author's age: linguistic steganography is intrinsically sensitive to model
distribution fidelity, finite-precision artifacts, active text edits, model
synchronization, traffic metadata, and the chosen warden/threat model.

## Major remaining gaps and mitigations

- **Detectability:** arithmetic coding is closer to the model distribution than
  ordinal buckets, but top-N truncation and quantization still alter it.
  Benchmark each exact configuration against statistical and learned
  steganalyzers; do not market it as undetectable.
- **No stego secret:** add a separately reviewed keyed sampling/framing design
  if deniability against a codec-aware observer is required. Encrypting the
  payload alone does not hide that a carrier was generated by this protocol.
- **Active wardens:** exact-text mode cannot survive edits. If the transport can
  normalize or paraphrase text, use a binary-safe carrier or a separately
  designed robust code with redundancy and authenticated candidate recovery.
- **Synchronization:** keep the model local, pin every artifact and setting,
  compare fingerprints, and prefer the same inference device/runtime. Avoid
  nondeterministic remote model APIs.
- **Length and timing:** batch, pad, and schedule at the application/carrier
  layer according to a concrete traffic-analysis threat model. Compact mode is
  intentionally length revealing.
- **Context and performance:** choose a model whose context window fits the
  expected cover, keep messages short, and impose time/token quotas. A larger
  model is not automatically safer.

Arithmetic coding here is mathematically conventional and covered by exact
round-trip tests. That does not constitute a cryptographic proof of
steganographic security. Useful primary research includes [Neural Linguistic
Steganography](https://aclanthology.org/D19-1115/), [provably secure generative
linguistic steganography](https://aclanthology.org/2020.emnlp-main.22/),
[Meteor](https://eprint.iacr.org/2021/686),
[Discop](https://doi.org/10.1109/SP46215.2023.10179287), [robust LLM
steganography](https://arxiv.org/abs/2504.08977), and [finite-precision
steganalysis](https://aclanthology.org/2026.findings-acl.1013/).
