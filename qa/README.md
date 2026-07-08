# HYDRA-MSG QA workspace

`qa/` contains validation scripts, vector tooling, fuzzing workspace folders, and release evidence helpers.

## Navigation

- [Main README](../README.md)
- [CI helpers](ci/README.md)
- [Fuzzing workspace](fuzz/README.md)
- [Vector generator](tools/vector-gen/README.md)
- [Validation docs](../docs/validation/release-criteria.md)

## Contents

```text
qa/
├── ci/       reusable CI/local-check scripts
├── fuzz/     fuzzing workspace
├── vectors/  generated vector artifacts
└── tools/    validation and vector-generation tooling
```

## Rules

- `qa/` is validation infrastructure, not protocol specification.
- Protocol authority lives in `docs/spec/`.
- Runtime implementation source lives in `crates/`.
- Script existence is not proof that validation passed.
- Passing evidence is the successful output from running the relevant script on the active repo state.

## Main commands

Unix:

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
