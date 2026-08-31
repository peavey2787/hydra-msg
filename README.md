# HYDRA-MSG

[![CI](https://github.com/peavey2787/hydra-msg/actions/workflows/ci.yml/badge.svg)](https://github.com/peavey2787/hydra-msg/actions/workflows/ci.yml)

HYDRA-MSG is a Rust/WASM encrypted messaging SDK for app developers.

It gives apps a small public API for identities, contacts, handshakes, encrypted messages, attachments, small lobbies, anonymous authorization tokens, encrypted local state, and encrypted backups.

<div align="center">
  <img width="550" alt="hydra-logo" src="https://github.com/user-attachments/assets/04998c19-8550-43e4-b980-a95b0660e1b4" />
</div>

### **Steganographic text carrier**

The workspace includes `hydra-stego`, an optional carrier adapter that turns
compact authenticated HYDRA envelopes into reversible text carriers.
Applications select normal padded bytes or a stego profile for each
message. The instant deterministic profile needs no model; the other profiles
use a local language model. Cover mode retains HYDRA's encryption,
authentication, ratchet, and replay checks while intentionally using a
length-revealing compact envelope.

```rust
use hydra_stego::{Stego, StegoError, StegoProfile};

fn cover_packet(encrypted_compact_envelope: &[u8]) -> Result<String, StegoError> {
    // Pure Rust: no model, tokenizer, Python runtime, or network request.
    Stego::new().encode(encrypted_compact_envelope, StegoProfile::Deterministic)
}

fn recover_packet(cover: &str) -> Result<Vec<u8>, StegoError> {
    Stego::new().decode(cover, StegoProfile::Deterministic)
}
```

See the [steganographic LAN chat](examples/stego_lan_chat/README.md) for a
two-browser WebRTC demo with a per-message carrier selector, four downloadable
local AI models, live download/load progress, a hardware-informed
recommendation, and automatic LAN rendezvous and session setup.
The demo offers a zero-model CFG/lexical/register profile with four
newline-delimited logfmt event families (build, metric, deploy, and trace), a
leading simulated timestamp on every record, family-correlated actor/context/action
vocabularies, intermittent randomized technical identifiers, and bounded numeric
metric/progress surface values. A slow probability-weighted arithmetic profile
and two constant-inference profiles provide the model-backed alternatives: a
compact Unicode variation-selector layer and printable hybrid prose. The
deterministic profile is instant but has a public, fingerprintable grammar. Its
first record carries 24-28 framed bits and later records carry 29-33 bits.
Passive modal chains, split-infinitive adverb insertion, conversational purpose
tails, and random delimiter switching are not part of the deterministic grammar.
None promises undetectability, anonymity, or semantic rewrite robustness. See the crate's [security
boundary and deployment constraints](crates/hydra-stego/README.md#security-status)
before production deployment.

## Navigation

- [How HYDRA messaging works](docs/impl/message-flow/README.md)
- [Spec docs and repo structure](docs/spec/README.md)
- [Crates](crates/README.md)
- [Examples](examples/README.md)
- [Public developer API](docs/spec/public-developer-api.md)
- [Benchmark notes](docs/validation/benchmarks/benchmark-results.md)

## Simple mental model


```text
open encrypted local HYDRA store
  -> create or import your identity
  -> exchange contact cards over any app carrier
  -> establish a session with the contact
  -> send encrypted HYDRA envelopes over any app carrier
```

A normal HYDRA message is key/session based: the receiver needs peer key material and an active session to decrypt. Apps can support anonymous-feeling chats by using one-time HYDRA identities and contact cards, but unlinkability across chats requires fresh identities per chat/lobby and no contact-card reuse. Relays only see opaque HYDRA bytes, but they may still see timing, IP, and routing metadata unless the carrier layer hides that too.

Current storage boundary: normal Native/CLI local state is always opened with a state password and sealed into `state.hydra`. Browser/WASM apps that need durable state use IndexedDB through `WasmHydra.openPersistent(name, password)` and explicitly commit changes with `await hydra.flush()`; tests and benchmarks can choose `WasmHydra.openEphemeral(name, password)` for in-memory state. Live 1:1 ratchet/skipped-key state is never persisted, peers retain authenticated generation floors across fresh handshakes, and browser apps can retain `flushAndStateFreshnessAnchor()` output with an external witness to detect rollback of an otherwise valid IndexedDB snapshot. State passwords, backup passwords, and identity seed passwords use per-record scrypt parameters and random salts before AEAD wrapping. New interactive records use `N=2^17, r=8, p=1` (`high-security` uses `N=2^18`); exact legacy profile tuples remain read-compatible and are transparently upgraded when the corresponding password is successfully used. Current contact cards expose only the public verification key by default; labeled cards are explicit. Current lobby invites expose the lobby id and max-member policy by default; labels and member lists are explicit. Current anonymous authorization is a one-time bearer-token stopgap for scope/action checks, separate from contact identity and not a blind-credential system.

Transport sizing boundary: apps configure only `hydra.set_packet_size(bytes)`. HYDRA then picks the largest padded packet class that fits, splits larger messages internally, and returns one or more opaque HYDRA packets from `send()`. App code sends every returned packet and feeds each incoming packet to `receive()`; it never sees fragment ids, part counts, chunk records, or session internals.

Session-security boundary: every encrypted envelope advances a one-way ratchet that protects erased past message material. Apps can optionally set a per-contact fresh-session cadence. An interval of one permits one outbound logical message, then blocks the next send until the app carries a fresh authenticated hybrid handshake with the peer. This bounds use of one session but does not claim zero exposure during a live endpoint compromise or automatic post-compromise healing.

For the detailed flow, see [How HYDRA messaging works](docs/impl/message-flow/README.md).

## Super-simple app shape

Bob's app imports Alice's contact card, starts a session, and sends a message:

```rust
use hydra_msg::{Hydra, HydraMessage, HydraResult};

fn bob_sends_to_alice() -> HydraResult<()> {
    // Open Bob's local HYDRA store for this app/device.
    let mut bob = Hydra::open_default("bob-state-password")?;

    // Create or import Bob's identity, then unlock it for this run.
    let bob_id = bob.generate_id("bob-password")?;
    bob.set_active_id(bob_id, "bob-password")?;

    // Alice's contact card arrives through the app carrier:
    // QR, invite link, WebRTC, relay, mailbox, file, or manual copy/paste.
    let alice_card = app_wait_for_alice_contact_card()?;
    let alice = bob.add_contact(alice_card)?;

    // Optional but recommended: compare the safety code with Alice through
    // another channel before showing the contact as verified in the app UI.
    // bob.verify_contact(alice.id(), confirmed_safety_code)?;

    // Create a HYDRA handshake offer and send those opaque bytes to Alice.
    let offer = bob.init_handshake(alice.id())?;
    app_send_to_alice(offer.as_bytes())?;

    // Wait for Alice's canonical RESP, emit FINISH, and send FINISH back.
    let answer = app_wait_for_alice_answer()?;
    let finish = bob.finish_handshake(answer)?;
    app_send_to_alice(finish.as_bytes())?;
    // Alice calls accept_handshake_finish(finish) before becoming Established.

    // Encrypt a message for Alice. The app carrier sends each opaque packet.
    let packets = bob.send(alice.id(), HydraMessage::text("hello Alice"))?;
    for packet in packets {
        app_send_to_alice(packet.as_bytes())?;
    }

    Ok(())
}
```

Alice's app shares her contact card, answers Bob's handshake, and receives the message:

```rust
use hydra_msg::{Hydra, HydraResult};

fn alice_receives_from_bob() -> HydraResult<()> {
    // Open Alice's local HYDRA store for this app/device.
    let mut alice = Hydra::open_default("alice-state-password")?;

    // Create or import Alice's identity, then unlock it for this run.
    let alice_id = alice.generate_id("alice-password")?;
    alice.set_active_id(alice_id, "alice-password")?;

    // Share Alice's contact card with Bob through the app carrier.
    let alice_card = alice.create_contact_card()?;
    app_send_to_bob(alice_card)?;

    // Wait for Bob's opaque handshake offer, then create an answer.
    let offer = app_wait_for_bob_offer()?;
    let answer = alice.reply_handshake(offer)?;
    app_send_to_bob(answer.as_bytes())?;

    // Wait for Bob's authenticated FINISH. The responder remains provisional
    // until this succeeds.
    let finish = app_wait_for_bob_finish()?;
    alice.accept_handshake_finish(finish)?;

    // Feed each incoming HYDRA packet into the SDK until a message completes.
    let packet = app_wait_for_bob_message()?;
    if let Some(message) = alice.receive(packet)? {
        println!("Alice received: {}", message.text()?);
    }
    Ok(())
}
```

The `app_*` functions are your app's carrier layer. HYDRA does not care whether those bytes move over WebRTC, files, QR codes, HTTP, a relay, a mailbox, libp2p, or manual copy/paste.

Runnable examples are in [examples](examples/README.md).

## Release validation

`./qa/ci/check-all.sh` is the complete local validation gate. Linux and Windows both delegate to the same `qa/ci/run_all.py` orchestration so section ordering, skips, LCOV/CRAP, mutation, and fuzz policy have one source of truth; native wrappers contain only OS-specific launching details. It runs the normal workspace/static/example checks first, then the heavy evidence gates, and leaves a bounded coverage-guided fuzz campaign last.

```bash
./qa/ci/check-all.sh
```

On Windows, the user-facing launch/check/install entry points are `.cmd` files only; there is no paired launcher `.ps1` to invoke or unblock. Double-click `scripts\install-hydra-windows.cmd` once (or simply double-click `scripts\run-hydra-windows.cmd` or root `run-check-all-windows.cmd`, which self-register). The setup is per-user, requires no administrator rights, and does not change the user or machine PowerShell execution policy. After registration, these commands resolve by bare name from PowerShell or CMD:

```cmd
run-check-all-windows
run-hydra-windows
```

Launcher failures remain visible and wait for a keypress instead of flashing a console window and disappearing. The existing internal Windows QA implementation still uses PowerShell where appropriate, but users never need to launch those internal `.ps1` files directly.

Resume a failed release run at a named section instead of repeating earlier green gates:

```bash
./qa/ci/check-all.sh --from browser --skip-browser-install
./qa/ci/check-all.sh --from coverage
./qa/ci/check-all.sh --from coverage --through mutation
./qa/ci/check-all.sh --from mutation --skip-mutation-baseline
```

Skip the mutation baseline only when the same tree already passed its Rust tests; otherwise leave the baseline enabled so cargo-mutants can derive a safe timeout. Run `./qa/ci/check-all.sh --help` for every section and granular `--skip-*` option. The final fuzz campaign defaults to 256 runs per target. Use `--overnight` for a time-bounded campaign or `--deep-fuzz` for 100,000 runs per fast target and 1,000 runs for the deliberately slower stateful target.

## Repository layout

```text
crates/      maintained Rust components
examples/    runnable examples over the public SDK
qa/          local check scripts, fixtures, fuzzing, browser tests, and release evidence
scripts/     developer setup and release packaging/signing helpers
docs/        specs, implementation notes, validation notes, and release-governance docs
```

For the full folder map, see [Repository structure](docs/spec/README.md).

## Benchmark snapshot

```text
Latest manual release-candidate browser/server spot checks, 1 KiB payload:

Samsung Galaxy browser WASM:
  handshake avg:       ~17 ms
  send+receive avg:    ~0.2 ms

ASUS TUF A16 laptop, browser WASM:
  handshake avg:       ~10 ms
  send+receive avg:    ~0.2 ms

ASUS TUF A16 laptop, native/server:
  handshake avg:        5.5286 ms
  send+receive avg:     0.0421 ms

Older development snapshots also include desktop browser WASM and
BLU M8L Android Go measurements. Sub-millisecond send/receive differences
are benchmark-noise/harness dominated and should not be used to claim that one
runtime is universally faster than another.
```

See [Benchmark notes](docs/validation/benchmarks/benchmark-results.md) for the full table and evidence expectations.

## First-time developer setup

Install HYDRA's Rust QA tools, WASM tooling, Playwright browser binaries, optional nightly Miri/sanitizer components, and release-tool reminders with:

```bash
./scripts/setup-dev-env.sh
```

PowerShell:

```powershell
.\scripts\setup-dev-env.ps1
```

## Validation

The full release-complete gate is:

```bash
./qa/ci/check-all.sh
```

It includes workspace format/test/clippy checks, supply-chain checks, static policy gates, examples, WASM package checks, Miri, sanitizers, real-browser Playwright E2E, coverage, mutation testing, and the bounded coverage-guided fuzz campaign last. Release validation explicitly selects deep fuzz mode. Archive the generated logs and reports for release candidates as described in [Release criteria](docs/validation/release/release-criteria.md).

## Security and release governance

Security reporting and release governance are documented separately so the app-developer path stays simple:

- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)
- [Release criteria](docs/validation/release/release-criteria.md)
- [Release checklist](docs/validation/release/release-checklist.md)
- [Release artifacts](docs/validation/release/release-artifacts.md)
- [SBOM policy](docs/validation/release/sbom.md)
- [Reproducible builds](docs/validation/release/reproducible-builds.md)
- [Release signing](docs/validation/release/release-signing.md)

For security reports, use GitHub Private Vulnerability Reporting through [SECURITY.md](SECURITY.md). Production release artifacts are created per signed tag with the release scripts under `scripts/release/`.

## Acknowledgements

The conversation cover-text feature was inspired by
[nethical6/conversation-steganography](https://github.com/nethical6/conversation-steganography).
Thanks to the original creator for publishing the proof of concept and clearly
documenting its experimental security status.
