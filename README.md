# HYDRA-MSG

HYDRA-MSG is a Rust/WASM post-quantum encrypted messaging SDK. The current refactor goal is simple:

> Make HYDRA stupid-simple for app developers.

App developers should start with `crates/hydra-msg`, not the lower-level protocol crates and not the demo reference crates.

## Status

This repository is an active refactor worktree, not a final cryptographic standard. Protocol authority remains in `docs/spec/`, while the public developer API target lives in `docs/project/public-developer-api.md`.

Do not describe this project as independently reviewed, fully interoperable, or finally frozen until the release criteria in `docs/validation/release-criteria.md` are satisfied.

## Repository layout

```text
crates/               protocol/product Rust crates
  hydra-core          protocol constants, shared types, errors, domain labels
  hydra-crypto        fixed-suite crypto backend internals
  hydra-envelope      byte-exact envelope/header encoding and validation
  hydra-session       1:1 sessions, ratchets, replay handling, refresh, close
  hydra-group         group modes and lobby/group internals behind the facade
  hydra-msg           stupid-simple public developer facade
  hydra-msg-wasm      browser/mobile WASM bindings over hydra-msg
  hydra-msg-cli       developer CLI over hydra-msg

examples/             active copy-paste developer examples
  handshake_roundtrip contact cards, handshake, send/receive
  contact_card        contact-card create/add/verify/export/import flow
  attachment_roundtrip text + file + in-memory byte attachment flow
  lobby_roundtrip     lobby invite + recipient-tagged lobby send/receive flow
  mobile_perf_web     LAN web host for server and browser/device WASM benchmarks
  manual_file_carrier files on disk as a manual opaque-byte carrier
  webrtc_manual_carrier WebRTC DataChannel carrier after manual contact-card exchange
  hydra-app-core      app-domain demo reference, outside active workspace
  hydra-app           CLI/local browser GUI demo reference, outside active workspace

docs/project/         roadmap, public API target, audits, WASM/CLI docs
docs/spec/            protocol authority
docs/impl/            implementation notes
docs/validation/      release/freeze criteria and test-vector notes
qa/                   QA scripts, vector tooling, fuzz workspace, validation assets
```

## Stupid-simple Rust API shape

```rust
use hydra_msg::{Hydra, HydraMessage};

let mut hydra = Hydra::open("./hydra-msg-data")?;

let my_id = hydra.generate_id("password")?;
hydra.set_active_id(my_id, "password")?;

let my_card = hydra.create_contact_card()?;
let bob = hydra.add_contact(bob_card)?;
hydra.verify_contact(bob.id(), safety_code)?;

let offer = hydra.init_handshake(bob.id())?;
let answer = hydra.reply_handshake(offer)?;
hydra.finish_handshake(answer)?;

let envelope = hydra.send(
    bob.id(),
    HydraMessage::text("hello")
        .attach_file("./photo.jpg")?
        .attach_bytes("data.bin", bytes_here)?,
)?;

let data = hydra.receive(envelope)?;
println!("{}", data.text()?);
for attachment in data.attachments() {
    std::fs::write(attachment.filename(), attachment.bytes())?;
}
```

See `docs/project/public-developer-api.md` for the full public API list.

## Active examples

Run the primary public SDK examples from the repo root:

```powershell
cargo run --manifest-path examples/handshake_roundtrip/Cargo.toml
cargo run --manifest-path examples/contact_card/Cargo.toml
cargo run --manifest-path examples/attachment_roundtrip/Cargo.toml
cargo run --manifest-path examples/lobby_roundtrip/Cargo.toml
cargo run --release --manifest-path examples/mobile_perf_web/Cargo.toml -- 0.0.0.0:8788
cargo run --manifest-path examples/manual_file_carrier/Cargo.toml
cargo run --release --manifest-path examples/webrtc_manual_carrier/Cargo.toml -- 0.0.0.0:8789
```

Build the browser/mobile WASM benchmark package before running `mobile_perf_web`:

```powershell
wasm-pack build crates/hydra-msg-wasm --target web --release --out-dir ../../examples/mobile_perf_web/web/pkg
cargo run --release --manifest-path examples/mobile_perf_web/Cargo.toml -- 0.0.0.0:8788
```

Then open the LAN URL on a phone/tablet/browser and run the browser/device HYDRA WASM benchmark.

For the WebRTC carrier example, build its WASM package first:

```powershell
examples\webrtc_manual_carrier\scripts\build-wasm.ps1
cargo run --release --manifest-path examples/webrtc_manual_carrier/Cargo.toml -- 0.0.0.0:8789
```

That example requires manual/out-of-band contact-card exchange before WebRTC carries any HYDRA handshake bytes or encrypted envelopes.


## Real-world benchmark snapshot

Informal Rust/WASM browser benchmark runs reported during the refactor are promising:

```text
Samsung Galaxy S20 Ultra, browser WASM, 1 KiB payload:
  handshake avg:     10.0 ms
  send+receive avg:   0.0775 ms

ASUS TUF Ryzen 7 A16 laptop, browser WASM, 1 KiB payload:
  handshake avg:      5.7333 ms
  send+receive avg:   0.0521 ms

Desktop PC, browser WASM, 1 KiB payload:
  handshake avg:      4.6633 ms
  send+receive avg:   0.0412 ms

Older low-end tablet, browser WASM, 1 KiB payload:
  handshake avg:    162.5 ms
  send+receive avg:   1.27 ms
```

See `docs/project/benchmark-results.md` for the full table and caveats. These are user-reported real-world results, not the final P13 validation record.


## Validation scripts

Run the full workspace validation from the repo root:

```powershell
.\qa\ci\check-all.ps1
```

Run runnable examples and browser package checks separately:

```powershell
.\qa\ci\check-examples.ps1
```

Unix setup after ZIP extraction:

```bash
sh qa/ci/linux-permissions.sh
```

Unix equivalents:

```bash
./qa/ci/check-all.sh
./qa/ci/check-examples.sh
```

Do not run the Unix scripts with `sudo` unless Cargo/Rust is installed for root.

The full validation script runs formatting, workspace tests, clippy, docs/static checks, and vector checks. The example script runs native examples, compiles browser hosts, and builds the WASM packages so normal validation does not wait on example flows.

## Developer CLI

The new CLI is `hydra-msg-cli`, a thin utility over the public facade:

```powershell
cargo run -p hydra-msg-cli -- generate-id
cargo run -p hydra-msg-cli -- contact-card
cargo run -p hydra-msg-cli -- handshake-demo
cargo run -p hydra-msg-cli -- send-demo
cargo run -p hydra-msg-cli -- attachment-demo
cargo run -p hydra-msg-cli -- bench
cargo run -p hydra-msg-cli -- doctor
```

See `docs/project/hydra-msg-cli.md`.

Carrier ownership and carrier example rules are documented in `docs/project/carrier-examples.md`.

## Demo app status

`examples/hydra-app-core` and `examples/hydra-app` are demo reference crates kept outside the active workspace while useful flows are rewritten against `hydra-msg`.

They are not protocol authority, not the public API, and not part of the active release path.

## Source-control safety

Runtime data must not be committed. `hydra-msg-data/`, identity vaults, test identities, app runtime state, and local secrets stay out of git.
