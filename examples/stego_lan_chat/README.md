# HYDRA steganographic LAN chat

## Navigation

- [Main README](../../README.md)
- [How HYDRA messaging works](../../docs/impl/message-flow/README.md)
- [Spec docs and repo structure](../../docs/spec/README.md)
- [Crates](../../crates/README.md)
- [Examples](../README.md)
- [Public developer API](../../docs/spec/public-developer-api.md)
- [Benchmark notes](../../docs/validation/benchmarks/benchmark-results.md)
## Build and run on Windows

The AI runtime is bootstrapped automatically on first model load. You only
need a normal Python 3 installation available through `py`, `python`, or
`python3`. The AI model control is hidden while the zero-model deterministic
profile is selected. Choosing any AI-backed profile reveals one compact model
dropdown directly below the Stego Profile selector; choosing a model creates the
private `target/stego-model-runtime` environment, installs/repairs its
dependencies, and downloads/loads that model. The setup script remains
available as an optional pre-warm command, but is not required for normal use.

Build the browser package:

```powershell
examples\stego_lan_chat\scripts\build-wasm.ps1
```

Start the host:

```powershell
cargo run --release --manifest-path examples/stego_lan_chat/Cargo.toml -- 127.0.0.1:8790
```

Open <http://127.0.0.1:8790> in two browsers. They automatically connect and
can immediately use the default deterministic profile without a model. Switch
to Fast Unicode, Fast Hybrid, or Slow Arithmetic to reveal the AI model
dropdown; selecting a model downloads/loads it once for the shared LAN host and
enables all three AI-backed profiles. The other browser observes the same
host-side model state. To serve other devices on your LAN, bind
`0.0.0.0:8790`, use the host machine's LAN address, and permit that port in the
local firewall only for the intended network.

An older build script leaked a WASM-only linker flag and caused MinGW to report
`unrecognized option '-z'`. The current script sanitizes and restores
`RUSTFLAGS`. To repair a terminal that was polluted by an older version, run:

```powershell
$env:RUSTFLAGS = ($env:RUSTFLAGS -replace '(?:^|\s)-C\s+link-arg=-zstack-size=\d+(?=\s|$)', '').Trim()
```

## Build and run on Unix

```bash
examples/stego_lan_chat/scripts/build-wasm.sh
cargo run --release --manifest-path examples/stego_lan_chat/Cargo.toml -- 127.0.0.1:8790
```

As on Windows, the first AI model load creates and repairs the private Python
runtime automatically. `scripts/setup-model-runtime.sh` is optional if you
prefer to pre-warm it before launching the demo.

The WASM package lives under `web/pkg/`. The host serves nested `wasm-pack`
snippet modules with JavaScript MIME types, including paths such as
`pkg/snippets/.../inline0.js`.

The browser model catalog is loaded independently from WASM session startup. If
`web/pkg/` is missing or stale, the AI model choices are still available when an
AI-backed Stego Profile is selected, while the connection status reports the
WASM build command. A source checkout must run the build script above before the
encrypted browser session can start; runnable demo archives may include the
prebuilt `web/pkg/` output.

## Model choices

The main chat UI does not show model setup at all for the zero-model profile.
For an AI-backed profile it shows one compact dropdown under Stego Profile;
selecting an entry starts download/load automatically, and a compact inline
status/progress indicator appears only while that AI control is relevant. The
dropdown marks the host-recommended model using logical CPU count plus
browser-reported memory:

| Model | Intended use |
|---|---|
| SmolLM2 135M Instruct | Fastest first run, 8K context, and low-resource CPU machines. |
| SmolLM2 360M Instruct | Balanced small local model with an 8K context. |
| Qwen2.5 0.5B Instruct | Recommended on stronger machines for its longer context. |
| TinyLlama 1.1B Chat | Larger experimental option with the slowest CPU inference. |

Download sizes are estimates and upstream repositories can change. The first
selection downloads weights into the normal Hugging Face cache; later loads
reuse that cache. Set `HYDRA_STEGO_PYTHON` to use another prepared Python
executable. Float32 CPU inference is the demo default because reproducibility
matters more than throughput here. Slow arithmetic mode can take tens of
seconds for even a short encrypted message on CPU; decoding the same recently
generated carrier reuses a bounded candidate cache. Both fast modes perform
exactly 16 model-token selections regardless of payload size and decode without
model inference. After the initial load, the main chat header keeps a model
dropdown available so users can switch models without opening developer
details. While any cover is being generated, the chat displays an
indeterminate activity bar, elapsed time, and the current
encrypt/generate/send phase; the composer is disabled so inference cannot look
like an ignored click or create duplicate sends.

## The four stego profiles

The demo exposes four per-message choices:

| Profile | Model work | Capacity | Security/transport tradeoff |
|---|---:|---:|---|
| Instant zero-model machine-status text | None | 24-28 bits in the first record; 29-33 bits thereafter | Pure printable Rust table operations with four stable newline-delimited logfmt event-family schemas (build, metric, deploy, trace), leading surface-only monotonic timestamps, family-correlated actor/context/action pools, intermittent randomized technical identifiers, bounded numeric metric/progress values, a message-locked formal/standard/compact/terse register, and action-centric base verbs. Tolerates case, punctuation, whitespace, and numeric-decoration changes, but its public grammar, schema frequencies, substitutions, and length remain fingerprintable; paraphrasing breaks it. Best contextual fit: mixed CI/build/metrics/deployment feeds. |
| Super fast Unicode | Fixed 16 visible tokens | One encrypted byte per trailing Unicode variation selector | Compact, but easy to identify by code-point inspection and fragile under normalization or selector stripping. |
| Super fast hybrid prose | Fixed 16 visible tokens | Five encrypted bytes per varied grammatical sentence | Uses printable words only and tolerates case, punctuation, and whitespace normalization. Its handcrafted distribution and length remain detectable; paraphrasing breaks it. |
| Slow, better stego | One inference for every arithmetic carrier token | Usually only a few encrypted bits per model token | Better model-distribution fidelity, but still not proven undetectable and too slow for large interactive messages on CPU. |

The fast Unicode profile frames the already encrypted HYDRA envelope, generates a
short probability-sampled visible cover, inserts an invisible separator, and
maps each framed byte to one Unicode variation selector. Decoding the fast
profile is linear-time Unicode extraction and does not run the model. It never
falls back to plaintext. This profile meets an interactive latency target by
accepting a substantial detectability and robustness downgrade, not by making
arithmetic generation magically parallel.

The fast hybrid profile uses that same short model cover as an introduction,
then selects among 32 sentence structures and ordinary grammatical choices for
openers, actions, topics, places, transitions, and tones. Each sentence
carries five framed bytes. There is no explicit separator or appended list.
The decoder scans for the authenticated frame while ignoring ASCII case,
punctuation, and whitespace, so ordinary surface normalization does not break
it. Changing words or their order does.

The deterministic profile carries 24-28 framed bits in its first record and
29-33 bits thereafter, but it does not prepend or consult model output. Every
physical line is logfmt and begins with `ts=<unix-seconds>.<micros>`. The stream
uses four stable event-family schemas rather than one rigid eight-key row:
build/test/package/artifact status records, compact metric samples,
deploy/release/rollout/sync records, and longer validation/retry/warning/failure
traces. Field counts and key ordering differ by family, while each family keeps
a consistent internal schema; the generator does not switch among YAML, pipe,
or double-colon formats.

The first timestamp is anchored to generation time. Later lines advance
monotonically with bounded microsecond-resolution jitter. Timestamp digits,
metric values, progress values, and optional numeric identifiers are all
surface-only and ignored by decoding.

Payload-bearing vocabulary is conditionally correlated with the selected event
family. Build records use runner/builder actors, build-pipeline contexts, build
actions, and build targets. Metric records use exporter/monitor actors and
telemetry contexts/actions. Deploy records use controller/deployer rollout
vocabulary. Trace records use checker/agent diagnostic vocabulary. The
planning/status/transfer/closing state rotates choices inside each family rather
than flattening all fields into one independent product distribution.

Machine execution style is carried separately as `mode`, while operations use
base-form verbs such as `queue`, `sample`, `stage`, and `inspect`. As a result,
constructions such as `to currently index`, `ready to currently approve`, and
`continues to currently tag` cannot be generated, and passive modal chains such
as `worker is expected to ...` remain absent by construction. Build and trace
families carry a technical evidence/scope detail; compact metric and deploy
families omit that slot.

Technical identifiers are deliberately intermittent rather than being appended
to every noun. Build/deploy/trace entities may receive a fresh bounded numeric
suffix; metric topics remain identifier-free. Progress phrases and metric
samples receive fresh bounded numeric values. Rewriting only those digits does
not affect decoding.

The remaining length is fundamental to this profile: after the 17-byte stego
frame, the first record carries 24-28 bits and subsequent records carry 29-33
bits. The theoretical bounds for a 262-byte envelope are 68 to 78 cover
records. The finite CFG is still better suited to operational telemetry than a
terse one-to-one reply, and the public schema/vocabulary distributions remain
fingerprintable under targeted steganalysis.

## Demo flow

1. Open the page in two browsers; the default zero-model profile connects
   without loading anything.
2. Watch the visible status advance from peer discovery through WebRTC and the
   HYDRA handshake.
3. Chat when the composer becomes enabled. Deterministic sends immediately; an
   AI-backed profile reveals the model dropdown directly below Stego Profile.
   Select a model once, then Fast Unicode, Fast Hybrid, and Slow Arithmetic all
   reuse that same ready host model.

The identity, contact-card, safety-code, rendezvous, WebRTC, HYDRA handshake,
event, and carrier diagnostics are collapsed behind **See Details**. The demo
automatically accepts the peer identity supplied by its trusted LAN rendezvous
host so it can remain zero-configuration. Production integrations must
authenticate discovery and perform a user-appropriate safety-code verification
ceremony rather than copying that demo shortcut.

The DataChannel adapter chunks large JSON carriers into 16 KiB pieces. WebRTC
itself encrypts the carrier, so this page demonstrates integration and exact
round trips; it does not simulate a passive observer seeing plaintext cover.

The main chat view deliberately shows both layers side by side. **Steganographic
carrier** is the unrelated-looking cover text sent over the demo transport;
**Decoded secret messages** is the original text recovered by the intended peer
after arithmetic decoding and HYDRA decryption. For example, if the secret is
`Hi`, seeing `Hi` in the decoded panel is the expected successful result—not
evidence that `Hi` was used as the carrier. The adjacent carrier panel shows the
actual generated text. During generation, the activity bar reports selected
visible or arithmetic cover tokens and elapsed time.

## Security boundary

Slow mode uses probability-weighted arithmetic coding. The existing fast modes
use an AI-generated visible cover plus either a variation-selector byte layer
or a public handcrafted prose grammar. Deterministic mode uses only its public
CFG and semantic tables. None promises undetectability, anonymity,
robustness to semantic edits, or traffic-analysis resistance. Compact HYDRA envelopes are
encrypted, authenticated, ratcheted, and replay-protected, but leak ciphertext
length.
Read the crate's [security status](../../crates/hydra-stego/README.md#security-status)
before adapting the demo.
