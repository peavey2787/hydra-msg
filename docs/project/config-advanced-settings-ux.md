# Config and Advanced settings UX

Status: P8 implementation note.

This document records the production settings boundary for `hydra-app`.

## Goal

Configuration must be understandable for normal users while still allowing
advanced operators to tune explicit policy values.

Normal users should not need to edit configuration to use HYDRA-MSG.
Advanced settings must be visible only behind a consistent `Advanced`
disclosure pattern.

## Source of truth

The active settings source is:

```text
examples/hydra-app/src/config.rs
```

Both CLI and GUI configuration changes go through `AppConfig::set`, which owns
key parsing and validation. GUI handlers do not parse individual settings except
to pass a key/value pair to this shared config logic.

## Simple settings model

The normal Settings screen shows status only:

- local data directory;
- storage-secret source;
- loopback GUI posture;
- reminder that no normal setting is required for basic chat.

Normal chat flow remains:

```text
identity -> contact trust -> chat
```

No normal setting is required to send local encrypted messages.

## Advanced controls

Advanced settings are grouped by risk and responsibility.

### Advanced rekey policy

These settings affect app policy thresholds for when sessions/groups should
rotate derived state:

- direct 1:1 rekey threshold;
- Lite group rekey threshold;
- Interactive group rekey threshold;
- Broadcast group rekey threshold;
- membership-change group rekey toggle;
- optional identity-rotation threshold after rekeys.

These settings do not redefine HYDRA protocol constants, wire formats, or
cryptographic primitives.

### Advanced local storage directory

The GUI shows the current `data_dir` for transparency, but does not provide a browser
control to change it. A mistaken value can make existing local identities, contacts,
messages, and recovery history appear absent, so changing the app-state root remains
a pre-startup/CLI workflow instead of a normal GUI setting.

### Advanced local GUI bind

Remote GUI binding is intentionally not configurable from the browser UI.
Non-loopback bind remains a CLI startup decision requiring:

```text
cargo run --manifest-path examples/hydra-app/Cargo.toml -- gui --addr <ip:port> --dangerous-allow-remote
```

This prevents a normal user from accidentally exposing the local GUI control
surface to the network.

## Validation

`AppConfig::set` rejects:

- unknown keys;
- empty data directories if configured through CLI/app config;
- data directories containing control characters if configured through CLI/app config;
- non-numeric numeric fields;
- zero rekey thresholds;
- rekey thresholds above `1_000_000` messages;
- identity rotation thresholds above `1_000_000`;
- invalid boolean values.

The GUI requires explicit Advanced confirmation for all current editable config
keys before it saves them.

## Tests

`examples/hydra-app/src/config.rs` includes tests for:

- valid rekey updates;
- invalid rekey bounds;
- invalid booleans;
- unknown keys;
- invalid data directories;
- excessive identity-rotation thresholds.

## Non-goals

P8 does not add:

- production relay/mailbox configuration;
- remote GUI binding from the browser UI;
- protocol constant configuration;
- crypto-suite selection;
- vector or wire-format configuration.
