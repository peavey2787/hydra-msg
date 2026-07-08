# HYDRA-MSG

HYDRA-MSG is a Rust/WASM post-quantum encrypted messaging SDK for app developers.

Use `crates/hydra-msg` for the Rust SDK, `crates/hydra-msg-wasm` for browser/mobile bindings, and `examples/` for runnable copy/paste flows.

## Navigation

- [Crates](crates/README.md)
- [Rust SDK facade](crates/hydra-msg/README.md)
- [WASM/JavaScript bindings](crates/hydra-msg-wasm/README.md)
- [Examples](examples/README.md)
- [QA and validation](qa/README.md)
- [CI helpers](qa/ci/README.md)
- [Public developer API](docs/project/public-developer-api.md)
- [WASM build notes](docs/project/wasm-javascript-bindings.md)
- [Benchmark notes](docs/project/benchmark-results.md)

## Repository layout

```text
crates/      maintained Rust components
examples/    runnable examples over the public SDK
qa/          validation scripts, vector tooling, and fuzzing workspace
docs/        API docs, protocol specs, implementation notes, and validation criteria
```

## Small working Rust example

```rust
use hydra_msg::{Hydra, HydraMessage, HydraResult};

fn main() -> HydraResult<()> {
    let _ = std::fs::remove_dir_all("target/readme-example/alice");
    let _ = std::fs::remove_dir_all("target/readme-example/bob");

    let mut alice = Hydra::open("target/readme-example/alice")?;
    let mut bob = Hydra::open("target/readme-example/bob")?;

    let alice_id = alice.generate_id("alice-password")?;
    let bob_id = bob.generate_id("bob-password")?;
    alice.set_active_id(alice_id, "alice-password")?;
    bob.set_active_id(bob_id, "bob-password")?;

    let alice_contact = bob.add_contact(alice.create_contact_card()?)?;
    let bob_contact = alice.add_contact(bob.create_contact_card()?)?;

    alice.verify_contact(bob_contact.id(), bob_contact.safety_code())?;
    bob.verify_contact(alice_contact.id(), alice_contact.safety_code())?;

    let answer = bob.reply_handshake(alice.init_handshake(bob_contact.id())?)?;
    alice.finish_handshake(answer)?;

    let envelope = alice.send(bob_contact.id(), HydraMessage::text("hello"))?;
    let received = bob.receive(envelope)?;

    println!("Bob received: {}", received.text()?);
    Ok(())
}
```

Run the complete version:

```bash
cargo run --manifest-path examples/handshake_roundtrip/Cargo.toml
```

## Build reusable WASM for a web app

Unix:

```bash
./qa/ci/build-wasm-web.sh
```

PowerShell:

```powershell
.\qa\ci\build-wasm-web.ps1
```

Output:

```text
target/hydra-msg-wasm/web/
```

Example browser hosts build their own `web/pkg/` folders only when testing those examples.

## Run validation

Unix after extracting a ZIP:

```bash
sh qa/ci/linux-permissions.sh
./qa/ci/check-all.sh
./qa/ci/check-examples.sh
```

PowerShell:

```powershell
.\qa\ci\check-all.ps1
.\qa\ci\check-examples.ps1
```

`check-all` runs workspace validation. `check-examples` runs runnable examples and browser package checks separately.

## Benchmark snapshot

```text
Samsung Galaxy S20 Ultra, browser WASM, 1 KiB payload:
  handshake avg:      10.0 ms
  send+receive avg:    0.0775 ms

ASUS TUF Ryzen 7 A16 laptop, browser WASM, 1 KiB payload:
  handshake avg:       5.7333 ms
  send+receive avg:    0.0521 ms

Desktop PC, browser WASM, 1 KiB payload:
  handshake avg:       4.6633 ms
  send+receive avg:    0.0412 ms

BLU M8L (Original), released August 2020, 1GB RAM, Android 11 Go edition,
browser WASM, 1 KiB payload:
  handshake avg:     162.5 ms
  send+receive avg:    1.27 ms
```

See [Benchmark notes](docs/project/benchmark-results.md) for the full table.

## Source-control safety

Do not commit runtime data, identity stores, test identities, app state, local secrets, `target/`, or generated browser `pkg/` folders.
