# HYDRA-MSG crash-consistency matrix

Status: implementation audit and regression gate for production persistence safety.

HYDRA persistence must be safe when process, OS, browser, filesystem, or storage
adapter failures interrupt a state transition. The required invariant is:

- durable state is either the last fully committed snapshot or the new fully
  authenticated snapshot;
- temporary files and aborted browser transactions are never treated as
  authoritative state;
- rollback evidence is repaired after a newer state is recovered;
- backup imports and destructive deletes are failure-atomic in memory and on
  disk; and
- storage failure is surfaced to the caller instead of falling back to plaintext,
  `localStorage`, or durable-looking in-memory state.

## Native filesystem matrix

| Failure point | Regression coverage | Expected safe result |
| --- | --- | --- |
| Write temp file | `crash_before_state_rename_leaves_old_state_authoritative` | Existing `state.hydra` remains authoritative; failed temp output is ignored/removed. |
| Sync temp file | `crash_before_state_rename_leaves_old_state_authoritative` | Existing `state.hydra` remains authoritative; no partial state is opened. |
| Rename/replace state | `crash_before_state_rename_leaves_old_state_authoritative` | Existing state remains openable if replacement did not complete. |
| Sync parent dir | `parent_dir_sync_failure_returns_error_but_leaves_openable_state` | Completed replacement is authenticated and openable; next open repairs rollback evidence. |
| Stale temp after crash | `crash_temp_file_is_ignored_and_removed_on_next_successful_write` | `state.hydra.tmp` is ignored on open and cleaned by the next successful write. |
| State replaced before rollback guard | `renamed_state_before_parent_sync_or_rollback_is_openable_and_repairs_guard` | Newer authenticated state is accepted and `state.hydra.rollback` is advanced. |
| Write rollback evidence | `rollback_evidence_write_failure_leaves_state_openable_and_repairable` | New state is still openable and rollback evidence is repaired on recovery. |
| Import backup | `backup_import_failure_is_atomic_in_memory_and_on_disk` | Failed import restores previous in-memory state and leaves prior disk state authoritative. |
| Delete identity | `delete_identity_failure_restores_memory_and_disk` | Failed delete restores the identity in memory and on disk. |
| Delete contact | `delete_contact_failure_restores_memory_and_disk` | Failed delete restores the contact in memory and on disk. |
| Delete message | `delete_message_failure_restores_memory_and_disk` | Failed delete restores the message in memory and on disk. |

Native fault injection is compiled only for tests through
`set_test_failpoint`. Production builds do not include the injection surface.

## Browser IndexedDB matrix

| Failure point | Regression coverage | Expected safe result |
| --- | --- | --- |
| IndexedDB flush | `runCrashConsistencyProbe` in the mobile perf web validation app | A completed transaction atomically replaces the opaque encrypted snapshot; an aborted transaction does not. |
| IndexedDB quota error | `runCrashConsistencyProbe` plus `userFacingStorageError` | Quota failure is surfaced to the app/user and does not fall back to plaintext, `localStorage`, or durable-looking memory. |
| Browser tab close mid-flush | `runCrashConsistencyProbe` aborts the write transaction | The prior IndexedDB snapshot remains authoritative after transaction abort. |

Browsers do not expose a safe deterministic way to intentionally exhaust real
site quota in a validation app. HYDRA therefore tests the user-facing quota
error path and the actual IndexedDB abort semantics separately, while the app
still probes `navigator.storage.estimate()` for real deployment diagnostics.

## Gates

The static gate is `qa/ci/reliability/check-crash-consistency.sh` with PowerShell parity in
`qa/ci/reliability/check-crash-consistency.ps1`. It is part of the normal tests/static
validation pipeline.
