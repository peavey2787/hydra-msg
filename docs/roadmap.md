# HYDRA group SRP size roadmap

## Navigation

- [Main README](../README.md)
- [Repository structure](spec/README.md)
- [Public developer API](spec/public-developer-api.md)
- [How HYDRA messaging works](impl/message-flow/README.md)
- [Benchmarks](validation/benchmark-results.md)

This roadmap replaces the prior active roadmap. The current goal is a focused SRP cleanup of the largest `hydra-group` files before calling the codebase production-ready or enterprise-grade.

Current target files:

```text
crates/hydra-group/src/commit.rs      1123 lines
crates/hydra-group/src/state.rs       1003 lines
crates/hydra-group/src/canonical.rs    858 lines
```

The work below is planning only until implementation is explicitly started.

## Rules and guidelines

1. **Organized file/folder structure.** File placement must make ownership obvious.
2. **Clear separation of concerns.** Each module owns one coherent responsibility.
3. **Consistent naming.** New module names must match the existing `hydra-group` domain language.
4. **Single Responsibility Principle.** Large files must be split by responsibility, not by arbitrary line count.
5. **No duplicated or unused code.** Shared helpers get one owner and one import path.
6. **Stay DRY.** Do not create parallel implementations of the same encoding, validation, state, or commit logic.
7. **Keep public behavior stable unless a bug is proven.** The SRP work should preserve the public exports from `crates/hydra-group/src/lib.rs` unless a later phase explicitly records a safe API adjustment.
8. **Keep tests close to the concern they prove.** Unit tests should move with the module they validate when a large file is split.
9. **Keep docs organized by purpose.** Only `docs/roadmap.md` belongs directly under `docs/`. Product docs belong under `docs/spec/`, `docs/impl/`, or `docs/validation/`. Assistant working notes and audits belong under `docs/project/`.
10. **Use one master validation path.** `qa/ci/check-all.*` remains the full correctness gate; example checks remain separate.
11. **Target smaller files without hiding complexity.** A split is successful only if each new file has a clear reason to exist.
12. **Before marking complete, ask:** Is this production-ready? Is it enterprise-grade? Is it mathematically sound? If not, record what remains.

## Minimal top-level folder structure

```text
crates/      maintained Rust components and system modules
docs/        specifications, implementation notes, validation notes, future work, and AI working notes
qa/          local correctness scripts, fixtures, vectors, fuzzing, and validation tools
examples/    runnable examples and small demo entry points
external/    third-party apps, libraries, or vendored outside material when needed
scripts/     automation that is not part of QA
```

## SRP targets

### `canonical.rs`

Current role: canonical byte encoding, validation helpers, commit-core encoding, change-payload encoding, hashes, confirmation tags, and tests.

Target ownership:

```text
crates/hydra-group/src/canonical/
  mod.rs              public module surface and re-exports
  primitives.rs       integer encoding, length-prefixed bytes, small shared encoding helpers
  roster.rs           roster-entry canonical encoding and roster canonical validation
  governance.rs       governance-policy canonical encoding and validation
  signatures.rs       commit-signature encoding and signature-set validation
  changes.rs          change-payload enum and change-payload encoding
  commit_core.rs      CommitCore and commit-core encoding
  hashes.rs           roster/governance/mode/change/commit hash helpers and confirmation tags
  tests.rs            canonical-format unit tests when tests are clearer outside submodules
```

Target result: no single canonical source file should own more than one encoding family.

### `state.rs`

Current role: private membership state, sender-chain state, replay state, group snapshots, group config, live group state, route-tag checks, replay mapping, roster hashing, and tests.

Target ownership:

```text
crates/hydra-group/src/state/
  mod.rs                 public module surface, GroupState, and high-level state methods
  membership_private.rs  private membership state snapshots, zeroization, and accessors
  sender_chain.rs        sender-chain cursors, skipped keys, resolution, and advancement
  replay.rs              replay state, accepted-message tracking, route-tag comparison
  snapshot.rs            snapshot structs and snapshot restore helpers
  config.rs              GroupStateConfig validation and construction support
  roster_view.rs         active sender roster views and roster-hash support
  tests.rs               state-level unit tests when tests span submodules
```

Target result: state construction, replay protection, and sender-chain mechanics should be separate concerns.

### `commit.rs`

Current role: commit-change types, commit plans, candidate state, prepare/apply/install flows, governance signature checks, parent validation, transition building, payload building, key-schedule commitments, removed-member handling, roster slot mapping, public-tree updates, membership material install, and tests.

Target ownership:

```text
crates/hydra-group/src/commit/
  mod.rs              public module surface and top-level prepare/apply/install functions
  types.rs            CommitChange, CommitPlan, PreparedCommit, CommitInstallResult, CandidateState
  prepare.rs          prepare_commit orchestration and commit-core construction
  apply.rs            apply_prepared_commit state update flow
  install.rs          install_prepared_commit fork/duplicate/apply behavior
  validation.rs       governance signatures, change-specific signatures, parent checks
  transition.rs       build_transition and counter progression
  payload.rs          build_change_payload and change-specific payload support
  key_schedule.rs     TreeKEM/direct-wrap commitment selection and validation
  tree_update.rs      update-path/public-tree application helpers
  membership.rs       removed-member handling, signer pruning, membership material install
  tests.rs            commit-flow unit tests when tests span submodules
```

Target result: commit orchestration should be thin; validation, transition calculation, payload construction, key-schedule logic, and tree updates should each have one owner.

## Phases and steps

### P0 — Baseline map and guardrails

Goal: create a precise map before moving code.

Steps:

- Record current line counts for `commit.rs`, `state.rs`, and `canonical.rs`.
- Record current public exports from `crates/hydra-group/src/lib.rs`.
- Map each top-level type/function in the three files to a target module.
- Identify tests that must move with each concern.
- Confirm no public behavior changes are part of this SRP roadmap.
- Define a practical file-size target: most files under 400 lines, with exceptions documented when a cohesive module must be larger.

### P1 — Split canonical encoding by encoding family

Goal: make canonical byte behavior easier to audit and harder to duplicate.

Steps:

- Create the `canonical/` module folder and keep `canonical::mod.rs` as the public surface.
- Move primitive encoding helpers first.
- Move roster encoding and roster canonical validation together.
- Move governance-policy encoding and governance validation together.
- Move commit-signature encoding and signature-set validation together.
- Move change-payload encoding together with `ChangePayload`.
- Move `CommitCore` and commit-core encoding together.
- Move hash and confirmation-tag helpers together.
- Preserve existing public re-exports from `hydra-group/src/lib.rs`.
- Run the full validation gate after the split.

### P2 — Split state mechanics by state responsibility

Goal: separate live group state from replay, sender-chain, snapshot, and private membership mechanics.

Steps:

- Create the `state/` module folder and keep `state::mod.rs` as the public surface.
- Move private membership state and snapshots into `membership_private.rs`.
- Move sender-chain cursors, skipped-key storage, and resolution logic into `sender_chain.rs`.
- Move replay tracking and accepted-message checks into `replay.rs`.
- Move snapshot structs and snapshot restore helpers into `snapshot.rs`.
- Move construction/config support into `config.rs` if it no longer belongs beside live state methods.
- Move roster-view and roster-hash helpers into `roster_view.rs` if they are not live-state methods.
- Preserve `GroupState` behavior and existing public re-exports.
- Run the full validation gate after the split.

### P3 — Split commit flow by commit responsibility

Goal: make commit preparation, validation, transition calculation, application, and install behavior independently reviewable.

Steps:

- Create the `commit/` module folder and keep `commit::mod.rs` as the public surface.
- Move commit data types into `types.rs`.
- Move prepare orchestration into `prepare.rs`.
- Move apply behavior into `apply.rs`.
- Move duplicate/fork/install behavior into `install.rs`.
- Move governance, change-specific, and parent validation into `validation.rs`.
- Move candidate-state transition calculation into `transition.rs`.
- Move change-payload construction into `payload.rs`.
- Move key-schedule commitment selection into `key_schedule.rs`.
- Move public-tree update helpers into `tree_update.rs`.
- Move removed-member and membership-material helpers into `membership.rs`.
- Preserve existing top-level public functions: `prepare_commit`, `apply_prepared_commit`, and `install_prepared_commit`.
- Run the full validation gate after the split.

### P4 — Tighten docs and ownership checks

Goal: ensure the new structure does not drift back into mixed-concern files.

Steps:

- Update `docs/spec/README.md` only if the structure map needs clearer `hydra-group` ownership notes.
- Add or update QA checks that report large Rust files above the chosen threshold.
- Add an allow-list mechanism for files that are large for a documented reason.
- Ensure Markdown links still resolve.
- Ensure README navigation still links back to the main README where required.
- Run docs checks after updates.

### P5 — Final validation and review gate

Goal: prove the SRP split preserved behavior.

Steps:

- Run `qa/ci/check-all.sh` or `qa/ci/check-all.ps1`.
- Run `qa/ci/check-examples.sh` or `qa/ci/check-examples.ps1`.
- Run `qa/ci/build-wasm-web.sh` or `qa/ci/build-wasm-web.ps1`.
- Compare public exports from before and after the split.
- Confirm no duplicated or unused code remains from moved helpers.
- Confirm line counts meet the target or document any justified exception.
- Record validation results in the progress report.

## Success criteria

This roadmap succeeds when:

1. `canonical.rs`, `state.rs`, and `commit.rs` are replaced by focused module folders.
2. Most new source files are under 400 lines.
3. Every new file has one clear responsibility.
4. Existing `hydra-group` public exports remain stable unless a safe change is explicitly documented.
5. Tests move with the concerns they validate.
6. `qa/ci/check-all.*` passes.
7. `qa/ci/check-examples.*` passes.
8. `qa/ci/build-wasm-web.*` passes.
9. Markdown links and README navigation pass.
10. The codebase is closer to production-ready and enterprise-grade, with remaining mathematical/security review gaps clearly recorded.

## Progress report

### 2026-07-08 — Current SRP roadmap created

Status: planned, not implemented.

- Replaced the prior active roadmap with this `hydra-group` SRP size roadmap.
- Kept rules/guidelines at the top, phases/steps in the middle, and progress report below.
- Confirmed current target file sizes:

```text
crates/hydra-group/src/commit.rs      1123 lines
crates/hydra-group/src/state.rs       1003 lines
crates/hydra-group/src/canonical.rs    858 lines
```

- No source modules were moved.
- No implementation work was started.
- Production-ready status: no. This SRP work, full validation, security review, and final vector/interoperability confirmation remain.
- Enterprise-grade status: no. The largest group files still need the planned ownership split and review.
- Mathematically sound status: not yet proven. The SRP work makes review easier, but proofs, adversarial checks, and external cryptography review remain separate validation work.
