# HYDRA carrier examples

## Navigation

- [Main README](../../README.md)
- [How HYDRA messaging works](message-flow/README.md)
- [Spec docs and repo structure](../spec/README.md)
- [Crates](../../crates/README.md)
- [Examples](../../examples/README.md)
- [Public developer API](../spec/public-developer-api.md)
- [Benchmark notes](../validation/benchmarks/benchmark-results.md)

HYDRA carriers move opaque bytes. They are not protocol authority.

The public `hydra-msg` facade owns:

```text
identity
contact trust
handshakes
session creation
encryption/decryption
message payload parsing
lobby envelope creation/parsing
```

Carriers own only byte movement:

```text
WebRTC
libp2p
HTTP
files
QR codes
manual copy/paste
relays
Kaspa pointers
mailboxes
```

A carrier must not inspect, reinterpret, mutate, or authorize HYDRA protocol
state. It can route bytes, retry bytes, persist bytes, or display bytes, but the
only code that decides whether those bytes are valid HYDRA data is the
`hydra-msg` facade.

## Manual file carrier

`examples/manual_file_carrier` writes HYDRA contact cards, handshake INIT, RESP, FINISH, and encrypted envelopes to files. The files are just a manual
carrier. The example exists to make the transport-agnostic rule obvious:

```text
HYDRA creates opaque bytes → file carrier moves bytes → HYDRA consumes bytes
```

## WebRTC manual carrier

`examples/webrtc_manual_carrier` demonstrates a browser WebRTC DataChannel as a
carrier over the `hydra-msg-wasm` facade.

The contact-card exchange is deliberately manual and out-of-band:

```text
1. Alice creates a HYDRA contact card.
2. Bob creates a HYDRA contact card.
3. Alice and Bob copy/paste or otherwise exchange contact cards manually.
4. Each user imports and verifies the other user's contact card.
5. Only then does the WebRTC DataChannel carry HYDRA handshake bytes.
6. After the HYDRA handshake, the DataChannel carries encrypted HYDRA envelopes.
```

The WebRTC example also uses manual SDP copy/paste for signaling so the example
has no signaling-server dependency. This SDP copy/paste is WebRTC setup only; it
is not HYDRA contact-card exchange and it is not protocol authority.

## Steganographic text carrier

`hydra-stego` transforms an already encrypted compact HYDRA envelope into
reversible cover text. It remains outside protocol authority:

```text
hydra-msg send_compact
  -> opaque authenticated length-revealing envelope
  -> hydra-stego deterministic telemetry or an AI-backed cover encoding
  -> application carrier
  -> hydra-stego cover decoding
  -> hydra-msg receive_compact and authenticate
```

Direct and cover-text messages may be interleaved on the same ratchet. Direct
mode uses normal `send` / `receive` fixed-size packets; cover mode uses
`send_compact` / `receive_compact`. The application records the carrier
representation alongside the transported value.

`examples/stego_lan_chat` demonstrates this boundary over browser WebRTC. Its
native host offers an instant zero-model CFG/lexical/register codec plus
several downloadable local AI models, hardware-informed recommendations,
content fingerprints, probability-weighted arithmetic coding, and
fixed-inference fast profiles. Both browser peers use that one host process for
AI modes. Every profile remains detectable;
no profile claims statistical
indistinguishability, anonymity, steganalysis resistance, or robustness to text
rewriting. The deterministic and hybrid profiles tolerate case, punctuation,
and whitespace normalization, but autocorrect, word replacement, or
translation can prevent recovery; HYDRA authentication remains the final
acceptance check.

Applications use the same small facade for every stego profile:

```rust
use hydra_stego::{Stego, StegoProfile};

let stego = Stego::new();
let cover = stego.encode(encrypted_compact_envelope, StegoProfile::Deterministic)?;
let recovered = stego.decode(&cover, StegoProfile::Deterministic)?;
```

AI-backed native integrations implement
`hydra_stego::model::LanguageModel`, create a fingerprint-pinned
`hydra_stego::model::ModelConfig`, and pass both to `Stego::with_model`.
The low-level arithmetic, Unicode, hybrid, and deterministic codecs are
implementation details rather than parallel public APIs. Both peers must pin
the same model fingerprint, tokenizer, scores, prompt, candidate filtering,
runtime, dtype, temperature, and arithmetic settings. The native process
adapter additionally requires an immutable model revision and uses bounded
startup/inference deadlines.

The arithmetic profile quantizes the model's temperature-scaled top-N
distribution into fixed integer frequencies. That improves distribution
fidelity over ordinal buckets but does not prove undetectability; top-N
truncation, finite-precision effects, model artifacts, and traffic metadata
remain.

## Future carriers

Future examples can add HTTP, libp2p, relays, Kaspa pointers, or mailbox nodes as
long as they follow the same rule:

```text
carrier in, carrier out, HYDRA remains the only protocol authority
```
