# HYDRA-MSG interop harness

## Navigation

- [Main README](../../../README.md)
- [Parent QA workspace](../../README.md)
- [Parent fixtures folder](../README.md)

The interop harness proves that frozen protocol artifacts and current v1-candidate state/backup artifacts remain consumable across runtime boundaries. It is intentionally separate from production crates.

The harness covers:

- protocol packet fixture → current session runtime;
- canonical outer-header fixture → current envelope encoder;
- current chunked encrypted state fixture → native runtime and WASM IndexedDB boundary;
- current chunked backup fixture → current backup verifier/importer;
- pre-v1 and unknown-future fixtures → current runtime fail-closed contract.

Run:

```bash
qa/ci/reliability/check-interop.sh
```

PowerShell:

```powershell
.\qa\ci\reliability\check-interop.ps1
```
