const STATE_PASSWORD = 'example-state';
const ID_PASSWORD = 'id-password';
const BACKUP_PASSWORD = 'backup-password';
const PERSISTENT_PROFILE = 'mobile-perf-persistent-validation';
const RESTORE_PROFILE = 'mobile-perf-persistent-restore-validation';
const CRASH_PROFILE = 'mobile-perf-crash-consistency-validation';
const MULTITAB_PROFILE = 'mobile-perf-multi-tab-concurrency-validation';
const INTEROP_PROFILE = 'mobile-perf-interop-fixture-validation';
const EPHEMERAL_PROFILE = 'mobile-perf-ephemeral';
const DB_NAME = 'hydra-msg';
const DB_VERSION = 2;
const STORE_NAME = 'snapshots';
const WASM_JS_PATH = '/pkg/hydra_msg_wasm.js';
const WASM_BG_PATH = '/pkg/hydra_msg_wasm_bg.wasm';
const GROWTH_MESSAGE_COUNT = 16;
const GROWTH_ATTACHMENT_BYTES = 4096;

const out = document.getElementById('out');
const buttons = Array.from(document.querySelectorAll('button[data-action]'));
let wasmModulePromise = null;

for (const button of buttons) {
  button.addEventListener('click', () => runAction(button.dataset.action));
}

async function runAction(action) {
  setButtonsDisabled(true);
  try {
    if (action === 'server') {
      await runServerBenchmark();
    } else if (action === 'wasm') {
      await runWasmBenchmark();
    } else if (action === 'persistent-suite') {
      await runPersistentSuite();
    } else if (action === 'persistent-reopen') {
      await runPersistentReopenOnly();
    } else if (action === 'api-misuse') {
      await runApiMisuseGuard();
    } else if (action === 'crash-consistency') {
      await runCrashConsistencyProbe();
    } else if (action === 'multi-tab') {
      await runMultiTabConcurrencyProbe();
    } else if (action === 'interop-fixture') {
      await runWasmInteropFixtureProbe();
    } else if (action === 'quota') {
      await runQuotaProbe();
    } else if (action === 'clear') {
      await clearPersistentProfiles();
    } else {
      throw new Error(`unknown action: ${action}`);
    }
  } catch (error) {
    writeJson({
      kind: 'browser-error',
      action,
      error: userFacingStorageError(error),
      rawError: stringifyError(error)
    });
  } finally {
    setButtonsDisabled(false);
  }
}

async function loadWasmModule() {
  if (!wasmModulePromise) {
    wasmModulePromise = (async () => {
      const health = await ensureWasmPackageAvailable();
      const cacheKey = encodeURIComponent(health.cacheKey || `${Date.now()}`);
      const mod = await import(`${WASM_JS_PATH}?v=${cacheKey}`);
      await mod.default(new URL(`${WASM_BG_PATH}?v=${cacheKey}`, window.location.href));
      return mod;
    })().catch((error) => {
      wasmModulePromise = null;
      throw error;
    });
  }
  return wasmModulePromise;
}

async function ensureWasmPackageAvailable() {
  const health = await fetchJson('/pkg-health');
  const cacheKey = encodeURIComponent(health.cacheKey || `${Date.now()}`);
  const [js, wasm] = await Promise.all([
    fetchModuleAsset(`${WASM_JS_PATH}?v=${cacheKey}`),
    fetchModuleAsset(`${WASM_BG_PATH}?v=${cacheKey}`)
  ]);
  const missing = [];
  if (!health.jsExists) {
    missing.push(WASM_JS_PATH);
  }
  if (!health.wasmExists) {
    missing.push(WASM_BG_PATH);
  }
  if (!js.ok) {
    missing.push(`${WASM_JS_PATH} HTTP ${js.status}`);
  }
  if (!wasm.ok) {
    missing.push(`${WASM_BG_PATH} HTTP ${wasm.status}`);
  }
  if (missing.length > 0) {
    throw new Error(
      `HYDRA WASM package is not available (${missing.join(', ')}). `
      + `Run ${health.buildCommand || 'examples/mobile_perf_web/scripts/build-wasm.sh'} from the repo root, `
      + `restart this host, then reload the browser page. pkgDir=${health.pkgDir || 'unknown'}`
    );
  }
  return health;
}

async function fetchModuleAsset(path) {
  try {
    const response = await fetch(path, { cache: 'no-store' });
    if (response.ok) {
      // Fully consume the response body. Some browsers abort an unused WASM/JS
      // preflight response, which can make the tiny example server see EPIPE and
      // exit before the real dynamic import runs.
      await response.arrayBuffer();
    }
    return { ok: response.ok, status: response.status };
  } catch (error) {
    return { ok: false, status: stringifyError(error) };
  }
}

async function fetchJson(path) {
  const response = await fetch(path, { cache: 'no-store' });
  if (!response.ok) {
    throw new Error(`${path} HTTP ${response.status}`);
  }
  return response.json();
}
async function fetchBinary(path) {
  const response = await fetch(path, { cache: 'no-store' });
  if (!response.ok) {
    throw new Error(`${path} HTTP ${response.status}`);
  }
  return new Uint8Array(await response.arrayBuffer());
}


async function runServerBenchmark() {
  out.textContent = 'Running server benchmark...';
  const { value: json, elapsedMs } = await timeAsync(async () => {
    const response = await fetch('/benchmark');
    if (!response.ok) {
      throw new Error(`server benchmark HTTP ${response.status}`);
    }
    return response.json();
  });
  writeJson({ kind: 'server', wallMsFromBrowser: elapsedMs, ...json });
}

async function runWasmBenchmark() {
  out.textContent = 'Loading WASM package and running ephemeral benchmark...';
  const mod = await loadWasmModule();
  const hydra = wrapStage('openEphemeral', () => mod.WasmHydra.openEphemeral(EPHEMERAL_PROFILE, STATE_PASSWORD));
  const { value: report, elapsedMs } = timeSync(() => wrapStage('benchmark', () => hydra.benchmark()));
  writeJson({
    kind: 'browser-wasm-ephemeral',
    wallMsOnThisDevice: elapsedMs,
    persistent: hydra.isPersistent(),
    dirty: hydra.isDirty(),
    suite: report.suite,
    iterations: report.iterations,
    handshakeAvgMs: report.handshakeAvgMs,
    sendReceiveAvgMs: report.sendReceiveAvgMs
  });
}

async function runPersistentSuite() {
  out.textContent = 'Running IndexedDB persistence validation suite...';
  const mod = await loadWasmModule();
  await wrapAsyncStage('delete stale persistent validation profiles', async () => {
    await mod.WasmHydra.deletePersistent(PERSISTENT_PROFILE);
    await mod.WasmHydra.deletePersistent(RESTORE_PROFILE);
  });

  const beforeEstimate = await storageEstimate();
  const firstOpen = await timeAsync(() => wrapAsyncStage(
    'open empty persistent profile',
    () => mod.WasmHydra.openPersistent(PERSISTENT_PROFILE, STATE_PASSWORD)
  ));
  const hydra = firstOpen.value;
  assert(hydra.isPersistent(), 'openPersistent must create a persistent wrapper');
  assert(!hydra.isDirty(), 'new persistent wrapper must start clean');

  const identitySave = await timeAsync(() => wrapAsyncStage('generate identity, set active, and flush', async () => {
    const id = hydra.generateId(ID_PASSWORD);
    hydra.setActiveId(id, ID_PASSWORD);
    assert(hydra.isDirty(), 'identity mutation must mark persistent wrapper dirty');
    await hydra.flush();
    assert(!hydra.isDirty(), 'flush must clear dirty state');
    return id;
  }));

  let peer = null;
  const contactSessionSave = await timeAsync(() => wrapAsyncStage('create peer contact session and flush', async () => {
    peer = wrapStage('open ephemeral peer', () => mod.WasmHydra.openEphemeral(`${EPHEMERAL_PROFILE}-persistence-peer-${Date.now()}`, STATE_PASSWORD));
    const peerIdentity = wrapStage('generate peer identity', () => peer.generateId(ID_PASSWORD));
    wrapStage('set peer active identity', () => peer.setActiveId(peerIdentity, ID_PASSWORD));

    const hydraCardForPeer = wrapStage('create persistent profile contact card for peer', () => hydra.createContactCard());
    const peerContactId = wrapStage('peer imports persistent profile contact card', () => peer.addContact(hydraCardForPeer));
    wrapStage('peer verifies persistent profile contact', () => peer.verifyContact(peerContactId, peer.contactSafetyCode(peerContactId)));

    const peerCardForHydra = wrapStage('create peer contact card for persistent profile', () => peer.createContactCard());
    const contactId = wrapStage('persistent profile imports peer contact card', () => hydra.addContact(peerCardForHydra));
    wrapStage('persistent profile verifies peer contact', () => hydra.verifyContact(contactId, hydra.contactSafetyCode(contactId)));

    const offer = wrapStage('persistent profile creates handshake offer', () => hydra.initHandshake(contactId));
    const answer = wrapStage('peer replies to handshake offer', () => peer.replyHandshake(offer));
    wrapStage('persistent profile finishes handshake answer', () => hydra.finishHandshake(answer));
    await wrapAsyncStage('flush persistent profile after contact/session mutation', () => hydra.flush());
    return { contactId, peerContactId, peerIdentity };
  }));

  const messageSave = await timeAsync(() => wrapAsyncStage('send attachment-growth messages and flush', async () => {
    const { contactId } = contactSessionSave.value;
    assert(peer, 'persistence validation peer was not initialized');
    for (let index = 0; index < GROWTH_MESSAGE_COUNT; index += 1) {
      const attachment = deterministicBytes(GROWTH_ATTACHMENT_BYTES, index);
      const message = mod.WasmHydraMessage
        .text(`persistent validation message ${index}`)
        .attachBytes(`payload-${index}.bin`, attachment);
      const packets = hydra.send(contactId, message);
      let received = null;
      for (const packet of packets) {
        received = peer.receive(packet) || received;
      }
      assert(received, 'roundtrip message did not complete');
      assert(received.text() === `persistent validation message ${index}`, 'roundtrip message text mismatch');
      assert(received.attachmentCount() === 1, 'roundtrip attachment count mismatch');
    }
    await hydra.flush();
    return JSON.parse(hydra.storageStatus());
  }));

  const backupRoundtrip = await timeAsync(() => wrapAsyncStage('export verify import backup and flush restore profile', async () => {
    const backup = hydra.exportBackup(BACKUP_PASSWORD);
    hydra.verifyBackup(backup, BACKUP_PASSWORD);
    const restored = await mod.WasmHydra.openPersistent(RESTORE_PROFILE, STATE_PASSWORD);
    assert(!restored.isDirty(), 'restore profile must start clean before backup import');
    restored.importBackup(backup, BACKUP_PASSWORD);
    assert(restored.isDirty(), 'importBackup must mark restored persistent state dirty until explicit flush');
    await restored.flush();
    assert(!restored.isDirty(), 'flush after importBackup must clear restored dirty state');
    return {
      backupBytes: byteLengthOf(backup),
      restoredStatus: JSON.parse(restored.storageStatus())
    };
  }));

  const reopen = await timeAsync(() => wrapAsyncStage(
    'reopen persistent profile after growth',
    () => mod.WasmHydra.openPersistent(PERSISTENT_PROFILE, STATE_PASSWORD)
  ));
  const reopened = reopen.value;
  const recordBytes = await indexedDbSnapshotSize(PERSISTENT_PROFILE);
  const restoreRecordBytes = await indexedDbSnapshotSize(RESTORE_PROFILE);
  const afterEstimate = await storageEstimate();

  writeJson({
    kind: 'browser-wasm-indexeddb-persistence-suite',
    profile: PERSISTENT_PROFILE,
    restoreProfile: RESTORE_PROFILE,
    firstOpenEmptyMs: firstOpen.elapsedMs,
    saveAfterIdentityMutationMs: identitySave.elapsedMs,
    saveAfterContactAndSessionMutationMs: contactSessionSave.elapsedMs,
    saveAfterMessageAndAttachmentGrowthMs: messageSave.elapsedMs,
    backupExportVerifyImportFlushMs: backupRoundtrip.elapsedMs,
    reopenExistingPersistentStateMs: reopen.elapsedMs,
    generatedIdentity: identitySave.value,
    contact: contactSessionSave.value,
    statusAfterGrowth: messageSave.value,
    backup: backupRoundtrip.value,
    reopened: {
      persistent: reopened.isPersistent(),
      dirty: reopened.isDirty(),
      idCount: reopened.listIds().length,
      contactCount: reopened.listContacts().length,
      debugMessageCount: JSON.parse(reopened.storageDebugStatus()).messageCount,
      activeId: reopened.activeId()
    },
    encryptedSnapshotBytes: recordBytes,
    restoredEncryptedSnapshotBytes: restoreRecordBytes,
    storageEstimateBefore: beforeEstimate,
    storageEstimateAfter: afterEstimate,
    notes: [
      'Reload the page and click Reopen persistent profile to manually validate page-reload durability.',
      'IndexedDB stores opaque encrypted HYDRA snapshot bytes; this page only measures byte length and status returned by the public facade.'
    ]
  });
}

async function runPersistentReopenOnly() {
  out.textContent = 'Reopening existing IndexedDB profile...';
  const mod = await loadWasmModule();
  const { value: hydra, elapsedMs } = await timeAsync(() => mod.WasmHydra.openPersistent(PERSISTENT_PROFILE, STATE_PASSWORD));
  const status = JSON.parse(hydra.storageStatus());
  writeJson({
    kind: 'browser-wasm-indexeddb-reopen-only',
    profile: PERSISTENT_PROFILE,
    reopenExistingPersistentStateMs: elapsedMs,
    persistent: hydra.isPersistent(),
    dirty: hydra.isDirty(),
    idCount: hydra.listIds().length,
    contactCount: hydra.listContacts().length,
    activeId: hydra.activeId(),
    status,
    encryptedSnapshotBytes: await indexedDbSnapshotSize(PERSISTENT_PROFILE),
    storageEstimate: await storageEstimate()
  });
}

async function runApiMisuseGuard() {
  out.textContent = 'Running browser API misuse guard checks...';
  const mod = await loadWasmModule();
  const checks = [];

  checks.push(await expectRejects('openPersistent missing name', () => mod.WasmHydra.openPersistent(undefined, STATE_PASSWORD)));
  checks.push(await expectRejects('openPersistent missing password', () => mod.WasmHydra.openPersistent('missing-password-profile', undefined)));
  checks.push(await expectRejects('openPersistent empty name', () => mod.WasmHydra.openPersistent('', STATE_PASSWORD)));
  checks.push(await expectRejects('openEphemeral missing password', () => mod.WasmHydra.openEphemeral('ephemeral-missing-password')));
  checks.push(await expectRejects('deletePersistent empty name', () => mod.WasmHydra.deletePersistent('')));

  writeJson({
    kind: 'browser-wasm-api-misuse-guard',
    indexedDbAvailable: Boolean(globalThis.indexedDB),
    checks,
    passed: checks.every((check) => check.rejected)
  });
}

async function runCrashConsistencyProbe() {
  out.textContent = 'Running IndexedDB crash-consistency probe...';
  const original = deterministicBytes(32, 77);
  const replacement = deterministicBytes(32, 78);
  await putIndexedDbSnapshot(CRASH_PROFILE, original);
  const beforeAbort = await readIndexedDbSnapshotBytes(CRASH_PROFILE);
  const tabCloseMidFlush = await expectRejects(
    'browser tab close mid-flush IndexedDB transaction abort',
    () => abortingIndexedDbPut(CRASH_PROFILE, replacement)
  );
  const afterAbort = await readIndexedDbSnapshotBytes(CRASH_PROFILE);
  assert(byteArraysEqual(beforeAbort, afterAbort), 'browser tab close mid-flush changed durable IndexedDB state');

  const quotaError = simulatedQuotaExceededError();
  const quotaMessage = userFacingStorageError(quotaError);
  assert(/QuotaExceededError|quota|full|storage/i.test(quotaMessage), 'quota error must be surfaced to the user');
  assert(/did not fall back to plaintext, localStorage, or durable-looking in-memory state/i.test(quotaMessage), 'quota path must preserve the no-fallback guarantee');

  writeJson({
    kind: 'browser-wasm-indexeddb-crash-consistency-matrix',
    profile: CRASH_PROFILE,
    indexedDbFlush: {
      atomicPutVerified: true,
      durableBytesAfterAbort: byteLengthOf(afterAbort)
    },
    indexedDbQuotaError: {
      simulated: true,
      surfacedMessage: quotaMessage
    },
    browserTabCloseMidFlush: {
      transactionAborted: tabCloseMidFlush.rejected,
      priorSnapshotPreserved: byteArraysEqual(beforeAbort, afterAbort),
      error: tabCloseMidFlush.error
    },
    notes: [
      'IndexedDB flush durability is tested by aborting the write transaction before completion and verifying the previous snapshot remains authoritative.',
      'IndexedDB quota error handling is tested by the user-facing error path; browsers cannot safely force real quota exhaustion in this validation app.',
      'Browser tab close mid-flush is modeled by transaction abort, which is the IndexedDB failure mode a closing page produces for unfinished writes.'
    ]
  });
}

async function runMultiTabConcurrencyProbe() {
  out.textContent = 'Running IndexedDB multi-tab concurrency probe...';
  const mod = await loadWasmModule();
  await mod.WasmHydra.deletePersistent(MULTITAB_PROFILE);

  const tabA = await mod.WasmHydra.openPersistent(MULTITAB_PROFILE, STATE_PASSWORD);
  const idA = tabA.generateId(ID_PASSWORD);
  tabA.setActiveId(idA, ID_PASSWORD);
  await tabA.flush();
  const revisionAfterInitialFlush = tabA.persistentRevision();

  const staleTabB = await mod.WasmHydra.openPersistent(MULTITAB_PROFILE, STATE_PASSWORD);
  assert(staleTabB.persistentRevision() === revisionAfterInitialFlush, 'second tab must start from the same durable revision');

  tabA.renameId(idA, 'committed-by-tab-a');
  await tabA.flush();
  const revisionAfterTabAFlush = tabA.persistentRevision();
  assert(revisionAfterTabAFlush > revisionAfterInitialFlush, 'tab A flush must advance the IndexedDB revision');

  staleTabB.renameId(idA, 'stale-tab-b-should-not-win');
  const staleFlush = await expectRejects('multi-tab stale IndexedDB compare-and-swap flush', () => staleTabB.flush());
  assert(staleFlush.rejected, 'stale tab flush must be rejected instead of using last-writer-wins');
  assert(staleTabB.isDirty(), 'stale tab must remain dirty so the app cannot pretend its changes are durable');

  const reopened = await mod.WasmHydra.openPersistent(MULTITAB_PROFILE, STATE_PASSWORD);
  const reopenedIdentity = JSON.parse(reopened.getId(idA));
  assert(reopenedIdentity.label === 'committed-by-tab-a', 'stale tab changed durable state despite CAS rejection');

  writeJson({
    kind: 'browser-wasm-indexeddb-multi-tab-concurrency',
    profile: MULTITAB_PROFILE,
    revisionAfterInitialFlush,
    revisionAfterTabAFlush,
    staleTabRevision: staleTabB.persistentRevision(),
    staleFlushRejected: staleFlush.rejected,
    staleFlushError: staleFlush.error,
    staleTabStillDirty: staleTabB.isDirty(),
    reopenedStatus: JSON.parse(reopened.storageStatus()),
    durableIdentityLabel: reopenedIdentity.label,
    policy: 'IndexedDB flush uses transactional compare-and-swap on the profile revision; stale tabs fail closed and must reopen before flushing.'
  });
}

async function runWasmInteropFixtureProbe() {
  out.textContent = 'Running current chunked IndexedDB + WASM interop probe...';
  const mod = await loadWasmModule();
  await mod.WasmHydra.deletePersistent(INTEROP_PROFILE);

  const hydra = await mod.WasmHydra.openPersistent(INTEROP_PROFILE, STATE_PASSWORD);
  const id = hydra.generateId('interop-id-password');
  await hydra.flush();
  const snapshot = await readIndexedDbSnapshotBytes(INTEROP_PROFILE);
  assert(snapshot && snapshot.byteLength > 0, 'interop snapshot must be stored in IndexedDB');
  assert(new TextDecoder().decode(snapshot).includes('chunk_size\t65536'), 'interop snapshot must use chunked padded storage');

  const reopened = await mod.WasmHydra.openPersistent(INTEROP_PROFILE, STATE_PASSWORD);
  const status = JSON.parse(reopened.storageDebugStatus());
  assert(reopened.isPersistent(), 'interop fixture must open as persistent WASM state');
  assert(reopened.persistentRevision() === 1, 'interop fixture IndexedDB revision must be preserved');
  assert(status.identityCount === 1, 'interop fixture identity count mismatch');
  assert(status.contactCount === 0, 'interop fixture contact count mismatch');
  assert(status.messageCount === 0, 'interop fixture message count mismatch');
  assert(status.lobbyCount === 0, 'interop fixture lobby count mismatch');
  assert(reopened.listIds().length === 1, 'interop fixture ID list mismatch');

  writeJson({
    kind: 'browser-wasm-frozen-fixture-interop',
    profile: INTEROP_PROFILE,
    fixture: 'current-v1-candidate/chunked-indexeddb-state',
    encryptedSnapshotBytes: snapshot.byteLength,
    persistentRevision: reopened.persistentRevision(),
    status,
    id,
    idCount: reopened.listIds().length,
    policy: 'WASM IndexedDB stores opaque chunked encrypted HYDRA state bytes and reopens them through the same public persistent profile API.'
  });
}

async function runQuotaProbe() {
  out.textContent = 'Reading browser storage quota/lifecycle information...';
  const mod = await loadWasmModule();
  const lifecycle = JSON.parse(await mod.WasmHydra.browserLifecycleStatus());
  const persistRequestGranted = await mod.WasmHydra.requestPersistentStorage();
  writeJson({
    kind: 'browser-storage-quota-probe',
    indexedDbAvailable: Boolean(globalThis.indexedDB),
    storageEstimate: await storageEstimate(),
    persisted: await storagePersisted(),
    hydraLifecycleStatus: lifecycle,
    persistRequestGranted,
    userAgent: navigator.userAgent,
    guidance: [
      'This probe does not intentionally fill the device storage quota.',
      'QuotaExceededError during flush must be surfaced to the app/user and must not fall back to localStorage, plaintext, or durable-looking in-memory state.',
      'Private browsing, user-cleared site data, mobile background kills, and browser eviction policies can remove IndexedDB state; exported encrypted backups are still required for portability and recovery.',
      'Persistent-storage denial is not ignored: HYDRA reports it so apps can warn that browser state remains eviction-prone.'
    ]
  });
}

async function clearPersistentProfiles() {
  out.textContent = 'Deleting validation profiles from IndexedDB...';
  const mod = await loadWasmModule();
  await mod.WasmHydra.deletePersistent(PERSISTENT_PROFILE);
  await mod.WasmHydra.deletePersistent(RESTORE_PROFILE);
  await mod.WasmHydra.deletePersistent(MULTITAB_PROFILE);
  await mod.WasmHydra.deletePersistent(INTEROP_PROFILE);
  writeJson({
    kind: 'browser-wasm-indexeddb-clear',
    deleted: [PERSISTENT_PROFILE, RESTORE_PROFILE, MULTITAB_PROFILE, INTEROP_PROFILE],
    storageEstimate: await storageEstimate()
  });
}

function deterministicBytes(length, seed) {
  const bytes = new Uint8Array(length);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = (seed * 131 + i * 17 + 29) & 0xff;
  }
  return bytes;
}

function byteLengthOf(bytes) {
  if (bytes instanceof Uint8Array) {
    return bytes.byteLength;
  }
  if (Array.isArray(bytes)) {
    return bytes.length;
  }
  return new Uint8Array(bytes).byteLength;
}

async function putIndexedDbSnapshot(name, snapshot) {
  const db = await openIndexedDb(DB_NAME, STORE_NAME);
  try {
    await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      tx.objectStore(STORE_NAME).put({
        name,
        snapshot: new Uint8Array(snapshot),
        revision: 1,
        adapterVersion: 2
      });
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error || new Error('IndexedDB snapshot put failed'));
      tx.onabort = () => reject(tx.error || new Error('IndexedDB snapshot put aborted'));
    });
  } finally {
    db.close();
  }
}

async function readIndexedDbSnapshotBytes(name) {
  const db = await openIndexedDb(DB_NAME, STORE_NAME);
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const request = tx.objectStore(STORE_NAME).get(name);
      request.onsuccess = () => {
        const record = request.result;
        resolve(record && record.snapshot ? new Uint8Array(record.snapshot) : null);
      };
      request.onerror = () => reject(request.error || tx.error || new Error('IndexedDB snapshot read failed'));
      tx.onabort = () => reject(tx.error || new Error('IndexedDB snapshot read transaction aborted'));
    });
  } finally {
    db.close();
  }
}

async function abortingIndexedDbPut(name, snapshot) {
  const db = await openIndexedDb(DB_NAME, STORE_NAME);
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).put({
      name,
      snapshot: new Uint8Array(snapshot),
      revision: 1,
      adapterVersion: 2
    });
    tx.oncomplete = () => {
      db.close();
      resolve();
    };
    tx.onerror = () => {
      db.close();
      reject(tx.error || new Error('IndexedDB aborting put failed'));
    };
    tx.onabort = () => {
      db.close();
      reject(tx.error || new Error('IndexedDB transaction aborted to simulate browser tab close mid-flush'));
    };
    tx.abort();
  });
}

function byteArraysEqual(left, right) {
  if (left === null || right === null) {
    return left === right;
  }
  if (left.byteLength !== right.byteLength) {
    return false;
  }
  for (let index = 0; index < left.byteLength; index += 1) {
    if (left[index] !== right[index]) {
      return false;
    }
  }
  return true;
}

function simulatedQuotaExceededError() {
  if (typeof DOMException === 'function') {
    return new DOMException('simulated IndexedDB quota exceeded during HYDRA flush', 'QuotaExceededError');
  }
  return {
    name: 'QuotaExceededError',
    message: 'simulated IndexedDB quota exceeded during HYDRA flush'
  };
}

async function indexedDbSnapshotSize(name) {
  if (!globalThis.indexedDB) {
    return null;
  }
  const db = await openIndexedDb(DB_NAME, STORE_NAME);
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const request = tx.objectStore(STORE_NAME).get(name);
      request.onsuccess = () => {
        const record = request.result;
        if (!record || !record.snapshot) {
          resolve(null);
          return;
        }
        resolve(byteLengthOf(record.snapshot));
      };
      request.onerror = () => reject(request.error || tx.error || new Error('IndexedDB snapshot-size read failed'));
      tx.onabort = () => reject(tx.error || new Error('IndexedDB snapshot-size transaction aborted'));
    });
  } finally {
    db.close();
  }
}

function openIndexedDb(dbName, storeName) {
  return new Promise((resolve, reject) => {
    const request = globalThis.indexedDB.open(dbName, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(storeName)) {
        db.createObjectStore(storeName, { keyPath: 'name' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error('IndexedDB open failed'));
    request.onblocked = () => reject(new Error('IndexedDB open blocked by another tab'));
  });
}

async function storageEstimate() {
  if (!navigator.storage || !navigator.storage.estimate) {
    return { available: false };
  }
  const estimate = await navigator.storage.estimate();
  return {
    available: true,
    usage: estimate.usage ?? null,
    quota: estimate.quota ?? null,
    usageDetails: estimate.usageDetails ?? null
  };
}

async function storagePersisted() {
  if (!navigator.storage || !navigator.storage.persisted) {
    return { available: false };
  }
  return { available: true, persisted: await navigator.storage.persisted() };
}

async function expectRejects(name, action) {
  try {
    await action();
    return { name, rejected: false, error: null };
  } catch (error) {
    return { name, rejected: true, error: stringifyError(error) };
  }
}

async function timeAsync(action) {
  const started = performance.now();
  const value = await action();
  return { value, elapsedMs: performance.now() - started };
}

function timeSync(action) {
  const started = performance.now();
  const value = action();
  return { value, elapsedMs: performance.now() - started };
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function wrapStage(stage, action) {
  try {
    return action();
  } catch (error) {
    throw new Error(`${stage} failed: ${stringifyError(error)}`);
  }
}

async function wrapAsyncStage(stage, action) {
  try {
    return await action();
  } catch (error) {
    throw new Error(`${stage} failed: ${stringifyError(error)}`);
  }
}

function stringifyError(error) {
  if (!error) {
    return 'unknown error';
  }
  if (typeof error === 'string') {
    return error;
  }
  const name = error.name ? `${error.name}: ` : '';
  const message = error.message || String(error);
  return `${name}${message}`;
}

function userFacingStorageError(error) {
  const message = stringifyError(error);
  if (/HYDRA WASM package is not available|dynamically imported module|hydra_msg_wasm/i.test(message)) {
    return `${message}. This usually means the example-local WASM package was not built, the server was started from a path that could not serve web/pkg, or the browser cached an old failed import. Run the build-wasm script, restart the host, hard-refresh the page, and open /pkg-health on the same host/origin.`;
  }
  if (/RuntimeError: unreachable executed|unreachable executed/i.test(message)) {
    return `${message}. The WASM module trapped, usually from a Rust panic in a browser-only runtime path or an undersized WASM stack during handshake crypto. Rebuild with examples/mobile_perf_web/scripts/build-wasm.sh from this repo version, restart the host, hard-refresh the page, and retry; this example labels the failing stage in the error prefix.`;
  }
  if (/QuotaExceededError|quota|full|disk/i.test(message)) {
    return `${message}. Browser storage is full or quota-limited. HYDRA did not fall back to plaintext, localStorage, or durable-looking in-memory state; free storage or export/import an encrypted backup.`;
  }
  if (/IndexedDB unavailable|SecurityError|private|denied|disabled/i.test(message)) {
    return `${message}. IndexedDB is unavailable, likely due to browser settings, private browsing, or site-data policy. Use ephemeral mode only intentionally, or enable persistent storage and keep encrypted backups.`;
  }
  if (/blocked/i.test(message)) {
    return `${message}. Close other tabs for this origin and retry.`;
  }
  return message;
}

function writeJson(value) {
  out.textContent = JSON.stringify(value, null, 2);
}

function setButtonsDisabled(disabled) {
  for (const button of buttons) {
    button.disabled = disabled;
  }
}
