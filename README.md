# HYDRA-MSG

HYDRA-MSG is a Rust/WASM post-quantum encrypted messaging SDK. The current refactor goal is simple:

> Make HYDRA stupid-simple for app developers.

App developers should start with `crates/hydra-msg`, not the lower-level protocol crates and not the retired demo app.

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
  hydra-app-core    old app-domain demo crate kept as reference
  hydra-app         old CLI/local browser GUI demo crate kept as reference

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
```

Build the browser/mobile WASM benchmark package before running `mobile_perf_web`:

```powershell
wasm-pack build crates/hydra-msg-wasm --target web --release --out-dir ../../examples/mobile_perf_web/web/pkg
cargo run --release --manifest-path examples/mobile_perf_web/Cargo.toml -- 0.0.0.0:8788
```

Then open the LAN URL on a phone/tablet/browser and run the browser/device HYDRA WASM benchmark.

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

## Demo app status

The old `hydra-app-core` and `hydra-app` crates are retired from the active workspace and kept under `examples/` only as reference material while useful flows are rewritten against `hydra-msg`.

They are not protocol authority, not the public API, and not part of the active release path.

## Source-control safety

Runtime data must not be committed. `hydra-msg-data/`, identity vaults, test identities, app runtime state, and local secrets stay out of git.
