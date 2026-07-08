# Storage, Backup, Recovery, and Rollback UX

Status: P7 implementation note.

P7 exposes existing app-core persistence and recovery protections in the local GUI without changing HYDRA protocol semantics or adding a production relay/mailbox service.

## Source ownership

- `hydra-app-core::storage_recovery` owns app-domain storage/recovery orchestration.
- `hydra-app` GUI routes expose local controls over that shared app-domain logic.
- GUI code does not parse backup formats, recovery manifests, signed checkpoint text, live-state records, or message-store bytes.
- CLI and GUI should converge on the shared app-core helpers in a later CLI/GUI parity milestone.

## User-visible flows

The Security screen now shows storage and rollback status:

- encrypted message database presence;
- conversation and message counts when the storage secret is available;
- live-state database presence;
- local live-state rollback sequence;
- signed checkpoint count;
- newest known signed checkpoint sequence;
- possible rollback warning when detected.

The GUI exposes these local actions:

- export encrypted recovery backup;
- inspect encrypted recovery backup manifest;
- export signed backup checkpoint history;
- check signed backup history against optional external checkpoint files/directories.

## Recovery backup boundary

Encrypted recovery backups may contain identity material and, optionally, encrypted message database records.

Backups remain encrypted with a user-provided backup password. The GUI does not store this password and sends it only in POST bodies to the local loopback GUI endpoint.

The default backup policy does not allow active-device cloning. The advanced `allow active-device clone` option is visible but off by default because preserving a source device ID can clone an active device.

## Signed checkpoint boundary

Signed checkpoint history is user-visible metadata that helps detect rollback of local live state. It does not contain plaintext messages, plaintext private keys, live protocol secrets, or storage keys.

If no live-state database exists, exporting a signed checkpoint initializes an empty encrypted live-state store, then signs and exports the checkpoint. This gives the user a continuity anchor before later live session/group state exists.

## Rollback behavior

If signed history or exported checkpoint files show that the local live-state database is older than a previously signed checkpoint, the GUI reports:

```text
Possible rollback detected.

This device is trying to use state older than a signed checkpoint you previously created.
Continuing may allow replayed messages, revoked devices, or old session keys to be reused.
```

The app-core check returns a `possible_rollback` status and the GUI displays the warning prominently. No override path is implemented in P7.

## Security boundaries

P7 does not add:

- plaintext backup export;
- server-side backup storage;
- production relay/mailbox behavior;
- silent active-device cloning;
- recovery of future group secrets for revoked devices;
- override of possible rollback warnings.

## Boundary audit

P7 boundary values are handled as follows:

- empty backup passwords are rejected;
- missing backup files are rejected by app-core read paths;
- optional external checkpoint paths may be empty;
- checkpoint path lists are split on newline, carriage return, comma, or semicolon;
- rollback warning is not downgraded to a normal success message;
- exporting a checkpoint updates live-state sequence exactly once through `save_with_signed_backup_history`;
- checking signed history does not mutate state.
