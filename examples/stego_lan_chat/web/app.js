import { base64ToBytes, bytesToBase64 } from './bytes.js';
import { decodeCarrier, describeCarrier, encodeCarrier } from './carrier.js';
import { LanPeer } from './lan-peer.js';

const ui = Object.fromEntries(
  [...document.querySelectorAll('[id]')].map(element => [element.id, element]),
);

let wasm;
let hydra;
let peerId;
let rendezvousId;
let peerRole;
let peerVerified = false;
let sessionReady = false;
let modelCatalog;
let modelReady = false;
let automationStarted = false;
let localOfferSent = false;
let localAnswerSent = false;
let remoteAnswerAccepted = false;
let hydraOfferSent = false;
let lastConnectionMessage = '';
let activeModelId;
let requestedModelId;
let modelLoading = false;
let modelCatalogError;
let sending = false;

const peer = new LanPeer(handlePeerMessage, handleRtcStatus);

function setStatus(element, message, state = 'pending') {
  element.textContent = message;
  element.classList.remove('pending', 'ok', 'bad');
  element.classList.add(state);
}

function setConnectionStatus(message, state = 'pending') {
  setStatus(ui['connection-status'], message, state);
  setStatus(ui['detail-connection-status'], message, state);
  if (message !== lastConnectionMessage) {
    lastConnectionMessage = message;
    appendLog(ui['event-log'], 'status', message);
  }
}

function appendLog(element, label, message) {
  const time = new Date().toLocaleTimeString();
  element.textContent += `[${time}] ${label}: ${message}\n\n`;
  element.scrollTop = element.scrollHeight;
}

function enableComposer(enabled) {
  ui.message.disabled = !enabled;
  ui['stego-profile'].disabled = !enabled;
  ui['ai-model-select'].disabled = modelLoading || !modelCatalog;
  ui.send.disabled = !enabled || (profileRequiresModel() && !activeModelReady());
}

function profileRequiresModel(profile = ui['stego-profile'].value) {
  return profile === 'fast' || profile === 'fast-hybrid' || profile === 'arithmetic';
}

function activeModelReady() {
  return modelReady && Boolean(activeModelId);
}

function renderAiModelControl() {
  const required = profileRequiresModel();
  ui['ai-model-control'].hidden = !required;
  ui['model-fingerprint-row'].hidden = !required;
  if (!required) return;

  if (modelCatalogError) {
    ui['ai-model-status'].textContent = `AI model catalog unavailable — ${modelCatalogError}`;
    ui['ai-model-status'].className = 'hint bad';
    return;
  }
  if (modelLoading) return;
  if (activeModelReady()) {
    const model = selectedModel(ui['ai-model-select']);
    ui['ai-model-status'].textContent = `${model?.label ?? 'Local AI model'} ready.`;
    ui['ai-model-status'].className = 'hint ok';
    return;
  }
  ui['ai-model-status'].textContent = 'Choose a model. Selecting it downloads and loads it locally.';
  ui['ai-model-status'].className = 'hint';
}

function renderProfileDescription() {
  ui['profile-description'].textContent = {
    deterministic: 'Instant zero-model mode emits newline-delimited logfmt telemetry using four stable event-family schemas: build, metric, deploy, and trace. Every record has a leading surface-only Unix timestamp with monotonic microsecond jitter, while actor, context, action, and target vocabularies are correlated with the selected event family instead of sampled from one flat product. Metric/progress numbers and intermittent technical identifiers are cosmetic and ignored by decoding. Action verbs stay in base form and mode is separate, so passive modal chains and split-infinitive adverb placement are absent by construction. It needs no model download and survives case/punctuation/whitespace/numeric normalization. The first record carries 24–28 framed bits and later records 29–33; its public grammar, schema frequencies, vocabulary, and expansion remain detectable, and changing data-bearing words or paraphrasing breaks it.',
    fast: 'Super fast generates only a short visible AI cover, then stores the encrypted HYDRA envelope in trailing Unicode variation selectors. It is high-capacity but easy to detect and fragile if text is normalized.',
    'fast-hybrid': 'Super fast hybrid mode uses a fixed 16-token AI introduction, then carries encrypted bits through varied grammatical sentence and word choices. It uses only printable prose and tolerates case, punctuation, and whitespace normalization. Its handcrafted distribution and length remain detectable, and paraphrasing breaks it.',
    arithmetic: 'Slow arithmetic mode encodes the encrypted envelope through model-token probabilities. It better follows the configured model distribution, but requires hundreds or thousands of sequential inferences.',
  }[ui['stego-profile'].value];
  renderAiModelControl();
  enableComposer(sessionReady && !sending);
}

function showSendActivity(message, state = 'pending', active = true) {
  ui['send-activity'].hidden = false;
  ui['send-progress'].hidden = !active;
  setStatus(ui['send-status'], message, state);
}

function beginCoverGenerationStatus(profile) {
  const control = { started: Date.now(), done: false };
  const label = {
    arithmetic: 'arithmetic cover',
    fast: 'fast Unicode cover',
    'fast-hybrid': 'fast hybrid prose cover',
    deterministic: 'deterministic zero-model cover',
  }[profile];
  if (profile === 'deterministic') {
    showSendActivity(`Running local ${label} encoding…`);
  } else {
    showSendActivity(`Starting local ${label} generation — 0 cover tokens generated`);
    void monitorCoverGeneration(control);
  }
  return control;
}

async function monitorCoverGeneration(control) {
  while (!control.done) {
    try {
      const status = await fetchJson('/api/stego/generation');
      if (status.active) {
        const seconds = Math.floor((Date.now() - control.started) / 1000);
        showSendActivity(
          `${status.phase} — ${status.tokens} cover tokens generated — ${seconds}s elapsed`,
        );
      }
    } catch {
      // The encode request reports failures; progress polling is best-effort UI only.
    }
    await delay(350);
  }
}

function delay(milliseconds) {
  return new Promise(resolve => window.setTimeout(resolve, milliseconds));
}

async function loadWasm() {
  if (wasm) return;
  try {
    wasm = await import('/pkg/hydra_msg_wasm.js');
    await wasm.default();
    const proto = wasm.WasmHydra?.prototype;
    if (typeof proto?.acceptHandshakeFinish !== 'function' || typeof proto?.acceptSessionRefreshFinish !== 'function') {
      throw new Error('stale HYDRA WASM package; rebuild it with examples/stego_lan_chat/scripts/build-wasm before starting this protocol version');
    }
  } catch (error) {
    wasm = undefined;
    throw new Error(
      `Browser WASM package unavailable (${error}). Run examples/stego_lan_chat/scripts/build-wasm before starting the host, then hard-refresh this page.`,
    );
  }
}

function requireSession() {
  if (!hydra || !peerId || !peerVerified || !sessionReady) {
    throw new Error('The encrypted peer session is not ready yet.');
  }
}

async function fetchJson(path, options) {
  const response = await fetch(path, options);
  if (!response.ok) throw new Error(await response.text());
  return response.json();
}

function recommendedModelId(catalog) {
  const cores = catalog.logicalCores || navigator.hardwareConcurrency || 1;
  const memory = navigator.deviceMemory;
  if (cores <= 4 || (memory && memory <= 4)) return 'smollm2-135m';
  if (cores <= 8 || (memory && memory <= 8)) return 'smollm2-360m';
  return 'qwen-0.5b';
}

function selectedModel(select = ui['ai-model-select']) {
  return modelCatalog?.models.find(entry => entry.id === select.value);
}

function modelLabel(modelId) {
  return modelCatalog?.models.find(entry => entry.id === modelId)?.label ?? 'Local AI model';
}

function applyModelStatus(status) {
  if (requestedModelId && status.modelId !== requestedModelId) return;

  modelLoading = Boolean(status.loading);
  const progress = Math.max(0, Math.min(100, Number(status.progress) || 0));
  ui['ai-model-progress'].value = progress;
  ui['ai-model-progress'].hidden = !modelLoading;
  ui['ai-model-progress'].setAttribute('aria-valuetext', status.phase || 'Preparing model');

  if (status.modelId && [...ui['ai-model-select'].options].some(option => option.value === status.modelId)) {
    ui['ai-model-select'].value = status.modelId;
  }

  if (status.ready && status.modelId) {
    modelReady = true;
    activeModelId = status.modelId;
    if (requestedModelId === status.modelId) requestedModelId = undefined;
    ui['ai-model-status'].textContent = `${status.label || modelLabel(status.modelId)} ready.`;
    ui['ai-model-status'].className = 'hint ok';
    ui['model-fingerprint'].textContent = status.fingerprint || 'available';
  } else if (status.loading) {
    modelReady = false;
    ui['ai-model-status'].textContent = `${status.phase || 'Preparing model'} · ${progress}%`;
    ui['ai-model-status'].className = 'hint pending';
  } else {
    modelReady = false;
    activeModelId = undefined;
    ui['model-fingerprint'].textContent = 'none';
    if (status.error) {
      requestedModelId = undefined;
      ui['ai-model-select'].value = '';
      ui['ai-model-status'].textContent = `Load failed — ${status.error}. Choose the model again to retry.`;
      ui['ai-model-status'].className = 'hint bad';
    } else {
      ui['ai-model-status'].textContent = 'Choose a model. Selecting it downloads and loads it locally.';
      ui['ai-model-status'].className = 'hint';
    }
  }

  renderAiModelControl();
  enableComposer(sessionReady && !sending);
}

async function refreshModelStatus() {
  const status = await fetchJson('/api/stego/status');
  modelCatalogError = undefined;
  applyModelStatus(status);
  return status;
}

async function monitorModelStatus() {
  while (true) {
    try {
      await refreshModelStatus();
    } catch (error) {
      modelCatalogError = String(error);
      renderAiModelControl();
    }
    await delay(500);
  }
}

async function initializeModelUi() {
  modelCatalog = await fetchJson('/api/stego/models');
  modelCatalogError = undefined;
  const recommended = recommendedModelId(modelCatalog);
  for (const model of modelCatalog.models) {
    const option = document.createElement('option');
    option.value = model.id;
    option.textContent = `${model.label}${model.id === recommended ? ' — recommended' : ''}`;
    ui['ai-model-select'].append(option);
  }
  ui['ai-model-select'].value = '';
  try {
    await refreshModelStatus();
  } catch (error) {
    modelCatalogError = String(error);
    renderAiModelControl();
  }
  void monitorModelStatus();
}

async function loadModel(model) {
  if (!model || modelLoading) return;
  if (modelReady && activeModelId === model.id) {
    renderAiModelControl();
    enableComposer(sessionReady && !sending);
    return;
  }

  requestedModelId = model.id;
  modelLoading = true;
  modelReady = false;
  ui['ai-model-progress'].hidden = false;
  ui['ai-model-progress'].value = 1;
  ui['ai-model-status'].textContent = `Preparing ${model.label} · 1%`;
  ui['ai-model-status'].className = 'hint pending';
  enableComposer(sessionReady && !sending);
  try {
    const status = await fetchJson(`/api/stego/select/${encodeURIComponent(model.id)}`, {
      method: 'POST',
    });
    applyModelStatus(status);
  } catch (error) {
    requestedModelId = undefined;
    modelLoading = false;
    modelReady = false;
    activeModelId = undefined;
    ui['ai-model-select'].value = '';
    ui['ai-model-progress'].hidden = true;
    ui['ai-model-status'].textContent = `Load failed — ${error}. Choose the model again to retry.`;
    ui['ai-model-status'].className = 'hint bad';
    enableComposer(sessionReady && !sending);
  }
}

ui['ai-model-select'].addEventListener('change', () => {
  const model = selectedModel();
  if (model) void loadModel(model);
});
ui['stego-profile'].addEventListener('change', renderProfileDescription);

ui['retry-connection'].addEventListener('click', () => window.location.reload());

function randomPeerId() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return [...bytes].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

async function startAutomaticSession() {
  if (automationStarted) return;
  automationStarted = true;
  try {
    setConnectionStatus('creating a private demo identity…');
    await loadWasm();
    hydra = wasm.WasmHydra.openEphemeral('stego-lan-chat-demo', 'demo-state-password');
    hydra.setPacketSize(4 * 1024);
    const identityId = hydra.generateId('demo-identity-password');
    hydra.setActiveId(identityId, 'demo-identity-password');
    const localCard = bytesToBase64(hydra.createContactCard());
    ui['local-identity'].textContent = identityId;
    ui['local-card'].value = localCard;
    setStatus(ui['identity-status'], 'ephemeral identity ready', 'ok');

    rendezvousId = randomPeerId();
    await fetchJson(`/api/lan/join/${rendezvousId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
      body: localCard,
    });
    window.addEventListener('beforeunload', leaveRendezvous, { once: true });
    await discoverAndConnect();
  } catch (error) {
    setConnectionStatus(`automatic connection failed — ${error}`, 'bad');
    appendLog(ui['event-log'], 'connection failed', String(error));
  }
}

function leaveRendezvous() {
  if (rendezvousId) navigator.sendBeacon(`/api/lan/leave/${rendezvousId}`);
}

async function discoverAndConnect() {
  while (!sessionReady) {
    const status = await fetchJson(`/api/lan/status/${rendezvousId}`);
    ui['peer-count'].textContent = `${status.peersSeen}/${status.targetPeers}`;
    if (status.state === 'waiting') {
      setConnectionStatus(`discovering local peers ${status.peersSeen}/${status.targetPeers}…`);
      await delay(500);
      continue;
    }

    peerRole = status.role;
    ui['peer-role'].textContent = peerRole;
    if (!peerId) {
      setConnectionStatus('local peer found — verifying demo identities…');
      peerId = hydra.addContact(base64ToBytes(status.peerCard));
      const safetyCode = hydra.contactSafetyCode(peerId);
      hydra.verifyContact(peerId, safetyCode);
      peerVerified = true;
      ui['peer-id'].textContent = peerId;
      ui['safety-code'].textContent = safetyCode;
      setStatus(ui['contact-status'], 'automatically verified for this trusted-LAN demo', 'ok');
    }

    if (peerRole === 'offer' && !localOfferSent) {
      setConnectionStatus('connecting to local peer — creating WebRTC offer…');
      const offer = await peer.createOffer();
      await postSignal('offer', offer);
      localOfferSent = true;
    } else if (peerRole === 'answer' && status.offer && !localAnswerSent) {
      setConnectionStatus('connecting to local peer — answering WebRTC offer…');
      const answer = await peer.createAnswer(status.offer);
      await postSignal('answer', answer);
      localAnswerSent = true;
    } else if (peerRole === 'offer' && status.answer && !remoteAnswerAccepted) {
      setConnectionStatus('connecting to local peer — accepting WebRTC answer…');
      await peer.acceptAnswer(status.answer);
      remoteAnswerAccepted = true;
    } else {
      setConnectionStatus('connecting to local peer…');
    }
    await delay(350);
  }
}

async function postSignal(kind, value) {
  await fetchJson(`/api/lan/${kind}/${rendezvousId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    body: value,
  });
}

function handleRtcStatus(status, ready = false) {
  setStatus(ui['rtc-status'], status, ready ? 'ok' : 'pending');
  if (!ready) return;
  setConnectionStatus('WebRTC connected — establishing encrypted HYDRA session…');
  if (peerRole === 'offer' && !hydraOfferSent) {
    hydraOfferSent = true;
    peer.send({ type: 'hydra-offer', bytes: bytesToBase64(hydra.initHandshake(peerId)) });
    setStatus(ui['session-status'], 'HYDRA offer sent', 'pending');
  }
}

ui.send.addEventListener('click', async () => {
  if (sending) return;
  sending = true;
  enableComposer(false);
  ui.send.textContent = 'Working…';
  let timing;
  try {
    requireSession();
    const message = ui.message.value.trim();
    if (!message) throw new Error('Enter a message.');
    const profile = ui['stego-profile'].value;
    showSendActivity('Encrypting the message with HYDRA…');
    if (profileRequiresModel(profile) && !modelReady) {
      throw new Error('Load a local cover model before using this AI-backed profile.');
    }
    const packet = hydra.sendCompactText(peerId, message);
    const profileLabel = {
      deterministic: 'instant zero-model machine-status text',
      fast: 'super-fast Unicode',
      'fast-hybrid': 'super-fast hybrid prose',
      arithmetic: 'slow arithmetic',
    }[profile];
    appendLog(
      ui['carrier-log'],
      'generating cover text',
      `Encoding an encrypted HYDRA envelope for a ${message.length}-character secret with the ${profileLabel} profile…`,
    );
    timing = beginCoverGenerationStatus(profile);
    const carrier = await encodeCarrier(packet, profile);
    timing.done = true;
    showSendActivity('Sending generated cover text to the local peer…');
    peer.send({ type: 'hydra-envelope', carrier });
    appendLog(
      ui['carrier-log'],
      `sent ${profileLabel} steganographic cover`,
      describeCarrier(carrier),
    );
    appendLog(ui['chat-log'], 'you — decoded secret', message);
    ui.message.value = '';
    const elapsed = timing ? ` in ${((Date.now() - timing.started) / 1000).toFixed(1)}s` : '';
    showSendActivity(`${profileLabel} steganographic cover sent${elapsed}; the peer will decode the original secret.`, 'ok', false);
  } catch (error) {
    if (timing) timing.done = true;
    appendLog(ui['chat-log'], 'send failed', String(error));
    showSendActivity(`Send failed — ${error}`, 'bad', false);
  } finally {
    sending = false;
    ui.send.textContent = 'Send message';
    enableComposer(sessionReady);
  }
});

ui.message.addEventListener('keydown', event => {
  if (event.key === 'Enter' && !event.shiftKey) {
    event.preventDefault();
    ui.send.click();
  }
});

async function handlePeerMessage(message) {
  try {
    if (!peerVerified) throw new Error('Peer identity is not ready.');
    switch (message.type) {
      case 'hydra-offer': {
        const answer = hydra.replyHandshake(base64ToBytes(message.bytes));
        peer.send({ type: 'hydra-answer', bytes: bytesToBase64(answer) });
        setStatus(ui['session-status'], 'RESP sent — waiting for FINISH', 'pending');
        break;
      }
      case 'hydra-answer': {
        const finish = hydra.finishHandshake(base64ToBytes(message.bytes));
        peer.send({ type: 'hydra-finish', bytes: bytesToBase64(finish) });
        sessionReady = true;
        finishSessionSetup();
        break;
      }
      case 'hydra-finish':
        hydra.acceptHandshakeFinish(base64ToBytes(message.bytes));
        sessionReady = true;
        finishSessionSetup();
        break;
      case 'hydra-envelope': {
        appendLog(
          ui['carrier-log'],
          {
            'fast-cover': 'received super-fast Unicode steganographic cover',
            'fast-hybrid-cover': 'received super-fast hybrid-prose steganographic cover',
            'deterministic-cover': 'received instant zero-model steganographic cover',
            'arithmetic-cover': 'received slow arithmetic steganographic cover',
            cover: 'received slow arithmetic steganographic cover',
          }[message.carrier.representation] ?? 'received unknown steganographic carrier',
          describeCarrier(message.carrier),
        );
        if (!sending) showSendActivity('Decoding incoming machine-status cover text…');
        const packet = await decodeCarrier(message.carrier);
        const received = hydra.receiveCompact(packet);
        if (received) {
          appendLog(ui['chat-log'], 'peer — decoded secret', received.text());
          if (!sending) {
            showSendActivity('Cover text decoded and HYDRA secret decrypted.', 'ok', false);
          }
        }
        break;
      }
      default:
        throw new Error(`Unknown peer message type: ${message.type}`);
    }
  } catch (error) {
    appendLog(ui['chat-log'], 'receive failed', String(error));
    setConnectionStatus(`encrypted session error — ${error}`, 'bad');
  }
}

function finishSessionSetup() {
  setStatus(ui['session-status'], 'established', 'ok');
  setConnectionStatus('connected to local peer — chat is ready', 'ok');
  enableComposer(true);
  ui.message.focus();
  if (rendezvousId) {
    void fetchJson(`/api/lan/leave/${rendezvousId}`, { method: 'POST' });
  }
}

async function boot() {
  enableComposer(false);
  renderProfileDescription();
  setConnectionStatus('starting the local encrypted session…');

  try {
    await initializeModelUi();
  } catch (error) {
    modelCatalogError = String(error);
    renderAiModelControl();
    appendLog(ui['event-log'], 'model catalog failed', String(error));
  }

  void startAutomaticSession();
}

void boot();
