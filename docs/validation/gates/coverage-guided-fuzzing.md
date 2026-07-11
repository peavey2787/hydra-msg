# Coverage-guided fuzzing

## Navigation

- [Main README](../../../README.md)
- [Validation index](../README.md)
- [Spec document index](../../spec/README.md)
- [Threat model](../../spec/threat-model.md)

## Targets

The `cargo-fuzz` harness lives in `qa/fuzz/cargo-fuzz/`. The validation scripts pass that nonstandard location explicitly with cargo-fuzz's `--fuzz-dir` option, so cargo-fuzz never falls back to a nonexistent root `fuzz/Cargo.toml`. It covers:

- `envelope_header_decoding` — outer header decoding.
- `protected_record_decoding` — protected-record decoding in every envelope class.
- `message_codec` — public message import/send/receive and attachment packaging paths.
- `storage_backup_chunk_parser` — encrypted state and chunked backup parser boundaries.
- `contact_card_parser` — contact-card preview/add/import boundaries.
- `handshake_offer_answer_parser` — handshake offer/answer parser and valid-offer mutation paths.
- `lobby_invite_parser` — lobby invite preview/join boundaries.
- `anonymous_auth_token_parser` — bearer-token, nullifier, accept, and revoke paths.
- `fragment_reassembly` — direct packet fragmentation/reassembly and malformed fragment delivery.
- `session_receive_state_machine` — lower-level session receive, replay, refresh, close, and malformed envelope paths.
- `group_commit_message_parser` — group canonical commit helpers and group message open/seal paths.

## Running campaigns

Install tooling:

```bash
./scripts/setup-dev-env.sh
```

Run the fuzz gate directly while debugging:

```bash
./qa/ci/fuzz/check-fuzz.sh
```

Run the release-candidate coverage-guided fuzz campaign through the full gate:

```bash
./qa/ci/check-all.sh
```

PowerShell:

```powershell
.\qa\ci\check-all.ps1
```

Evidence is written to `target/hydra-fuzz-evidence/` by default. Release managers should archive the command line, target list, run count, crash artifacts, and minimized reproducers.

## Release requirement

A release candidate must either:

- complete all listed coverage-guided fuzz targets without crashes for the release policy's configured run budget; or
- document every crash with a minimized reproducer, fix, and regression test before release.
