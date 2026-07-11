// Browser interop probe contract.
// This file documents the executable browser path implemented by
// examples/mobile_perf_web/web/app.js::runWasmInteropFixtureProbe.
// The probe creates a current v1-candidate persistent profile, flushes it to
// IndexedDB, confirms the stored opaque bytes use chunked padded storage, and
// reopens the same profile through WasmHydra.openPersistent.

export const HYDRA_INTEROP_BROWSER_PROBE = Object.freeze({
  kind: 'browser-wasm-frozen-fixture-interop',
  fixture: 'current-v1-candidate/chunked-indexeddb-state',
  wasmOpen: 'WasmHydra.openPersistent',
  indexedDbStore: 'hydra-msg/snapshots',
  storage: 'fixed-size encrypted chunks with padded final chunk',
  expected: {
    identityCount: 1,
    contactCount: 0,
    messageCount: 0,
    lobbyCount: 0,
    revision: 1
  }
});
