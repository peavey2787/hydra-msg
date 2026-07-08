# HYDRA-MSG checks

`qa/` contains local scripts, vector tooling, and fuzzing workspace folders.

## Navigation

- [Main README](../README.md)
- [Scripts](ci/README.md)
- [Fuzzing workspace](fuzz/README.md)
- [Vector generator](tools/vector-gen/README.md)
- [Release criteria](../docs/validation/release-criteria.md)

## Contents

```text
qa/
├── ci/       reusable local-check scripts
├── fuzz/     fuzzing workspace
├── vectors/  generated vector artifacts
└── tools/    validation and vector-generation tooling
```

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
