# Coverage-guided fuzzing

## Navigation

- [Main README](../../../README.md)
- [Validation index](../README.md)
- [Spec document index](../../spec/README.md)
- [Threat model](../../spec/threat-model.md)

## Targets

The cargo-fuzz harness lives in `qa/fuzz/cargo-fuzz/` and uses nightly Rust through the QA runners. The fast targets are:

- `envelope_header_decoding` — outer header decoding.
- `protected_record_decoding` — protected-record decoding in every envelope class.
- `message_codec` — in-memory message binary/state-line decoding and encode/decode round trips.
- `storage_backup_chunk_parser` — encrypted state and chunked backup parser boundaries.
- `contact_card_parser` — contact-card preview/add/import boundaries.
- `handshake_offer_answer_parser` — handshake offer/answer parser and valid-offer mutation paths.
- `lobby_invite_parser` — lobby invite preview/join boundaries.
- `anonymous_auth_token_parser` — bearer-token, nullifier, accept, and revoke paths.
- `fragment_reassembly` — direct packet fragmentation/reassembly and malformed fragment delivery.
- `session_receive_state_machine` — lower-level session receive, replay, refresh, close, and malformed envelope paths.
- `group_commit_message_parser` — group canonical commit helpers and group message open/seal paths.

The separately budgeted slow target is:

- `message_stateful_flow` — profile creation, identity/contact setup, handshake, encrypted send/receive, attachments, and tampered packet delivery.

Separating the two message targets prevents parser fuzzing from paying profile, filesystem, and handshake costs on every iteration.

## Compile preflight

Before any corpus execution begins, the fuzz gate builds every declared cargo-fuzz target.
This catches API drift or a broken late target immediately instead of after earlier campaigns
have consumed their full budgets.

## Running campaigns

Install tooling:

```bash
./scripts/setup-dev-env.sh
```

Default bounded smoke campaign, 256 iterations per target:

```bash
./qa/ci/check-all.sh --only fuzz
```

Time-bounded overnight campaign, 15 minutes per fast target and 5 minutes for the stateful target:

```bash
./qa/ci/check-all.sh --only fuzz --overnight
```

Deep campaign, 100,000 runs per fast target and 1,000 stateful runs:

```bash
./qa/ci/check-all.sh --only fuzz --deep-fuzz
```

Custom bounded campaign:

```bash
./qa/ci/check-all.sh --only fuzz --fuzz-runs 1000 --stateful-fuzz-runs 128
```

PowerShell uses `-Only fuzz`, `-Overnight`, `-DeepFuzz`, `-FuzzRuns`, and `-StatefulFuzzRuns`. Evidence is written to `target/hydra-fuzz-evidence/`.

## Release requirement

A release candidate must either complete the configured deep campaign without crashes or document every crash with a minimized reproducer, fix, and regression test. Archive the mode, target list, budgets, toolchain, crash artifacts, and minimized reproducers.
