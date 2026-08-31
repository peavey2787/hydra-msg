export const STEGO_DESCRIPTIONS = {
  off: "Encrypted sends HYDRA's normal padded encrypted packets. This is the simplest and most efficient carrier.",
  deterministic: 'stego-instant encodes the compact HYDRA envelope into structured machine-status telemetry. It needs no model, but its public grammar remains fingerprintable.',
  fast: 'stego-unicode uses a short AI-written visible cover plus trailing Unicode variation selectors. It is very fast and high-capacity, but the selectors are detectable and normalization can destroy them.',
  'fast-hybrid': 'stego hybrid uses a short AI introduction plus printable grammar choices. It is fast, human-readable, and tolerates case/punctuation/whitespace normalization, but its handcrafted distribution remains detectable.',
  arithmetic: 'stego-ai encodes through model-token probabilities for better model-distribution fidelity. It is much slower because generation proceeds token by token.',
};

export class StegoClient {
  constructor(onStatus) {
    this.onStatus = onStatus;
    this.catalog = undefined;
    this.activeModelId = undefined;
    this.loading = false;
    this.requestedModelId = undefined;
    this.statusTimer = undefined;
  }

  requiresModel(profile) {
    return ['fast', 'fast-hybrid', 'arithmetic'].includes(profile);
  }

  async initialize() {
    const response = await fetch('/api/stego/models', { cache: 'no-store' });
    if (!response.ok) throw new Error(await response.text());
    this.catalog = await response.json();
    this.statusTimer = window.setInterval(() => void this.refreshStatus(), 700);
    await this.refreshStatus();
    return this.catalog;
  }

  async selectModel(id) {
    if (!id) return;
    this.loading = true;
    this.requestedModelId = id;
    this.onStatus?.({ loading: true, progress: 1, phase: 'Preparing local AI model', modelId: id });
    try {
      const response = await fetch(`/api/stego/select/${encodeURIComponent(id)}`, { method: 'POST' });
      if (!response.ok) throw new Error(await response.text());
      const status = await response.json();
      this.applyStatus(status);
      return status;
    } finally {
      this.loading = false;
    }
  }

  async refreshStatus() {
    try {
      const response = await fetch('/api/stego/status', { cache: 'no-store' });
      if (!response.ok) throw new Error(await response.text());
      this.applyStatus(await response.json());
    } catch (error) {
      this.onStatus?.({ ready: false, loading: false, error: String(error) });
    }
  }

  applyStatus(status) {
    if (this.requestedModelId && status.modelId !== this.requestedModelId) return;
    this.loading = Boolean(status.loading);
    this.activeModelId = status.ready ? status.modelId : undefined;
    if (status.ready && status.modelId === this.requestedModelId) this.requestedModelId = undefined;
    if (status.error) this.requestedModelId = undefined;
    this.onStatus?.(status);
  }

  readyFor(profile) {
    return !this.requiresModel(profile) || Boolean(this.activeModelId);
  }

  async encode(profile, payload) {
    if (profile === 'off') throw new Error('Direct mode does not use stego encoding.');
    if (!this.readyFor(profile)) throw new Error('Choose and load an AI cover model first.');
    const response = await fetch(profileRoute(profile, 'hide'), { method: 'POST', body: payload });
    if (!response.ok) throw new Error(await response.text());
    return new TextDecoder().decode(await response.arrayBuffer());
  }

  async decode(profile, cover) {
    if (!this.readyFor(profile)) throw new Error('The matching AI cover model is not loaded.');
    const response = await fetch(profileRoute(profile, 'reveal'), {
      method: 'POST',
      body: new TextEncoder().encode(cover),
    });
    if (!response.ok) throw new Error(await response.text());
    return new Uint8Array(await response.arrayBuffer());
  }
}

function profileRoute(profile, direction) {
  const suffix = {
    deterministic: '-deterministic',
    fast: '-fast',
    'fast-hybrid': '-fast-hybrid',
    arithmetic: '',
  }[profile];
  if (suffix === undefined) throw new Error(`Unknown stego profile: ${profile}`);
  return `/api/stego/${direction}${suffix}`;
}
