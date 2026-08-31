import { bytesToBase64, randomHex } from './bytes.js';

const ID_KEY = 'hydra.gui.lan-id';

export class LanClient {
  constructor({ onPeers, onMessage, onStatus }) {
    this.id = sessionStorage.getItem(ID_KEY) || randomHex(16);
    sessionStorage.setItem(ID_KEY, this.id);
    this.onPeers = onPeers;
    this.onMessage = onMessage;
    this.onStatus = onStatus;
    this.running = false;
    this.card = undefined;
  }

  async start(contactCard) {
    this.card = bytesToBase64(contactCard);
    this.running = true;
    await this.register();
    void this.peerLoop();
    void this.inboxLoop();
  }

  async register() {
    const data = await fetchJson(`/api/lan/register/${this.id}`, {
      method: 'POST',
      body: this.card,
    });
    this.onStatus?.('connected');
    this.onPeers?.(data.peers ?? []);
  }

  async updateCard(contactCard) {
    this.card = bytesToBase64(contactCard);
    return this.register();
  }

  async send(peerId, kind, payload, tag) {
    const body = typeof payload === 'string' ? bytesToBase64(new TextEncoder().encode(payload)) : bytesToBase64(payload);
    const suffix = tag ? `/${encodeURIComponent(tag)}` : '';
    await fetchJson(`/api/lan/send/${this.id}/${peerId}/${kind}${suffix}`, { method: 'POST', body });
  }

  async peerLoop() {
    while (this.running) {
      try {
        const data = await fetchJson(`/api/lan/peers/${this.id}`);
        this.onStatus?.('connected');
        this.onPeers?.(data.peers ?? []);
      } catch (error) {
        this.onStatus?.('error', error);
        try { await this.register(); } catch { /* retry next loop */ }
      }
      await delay(850);
    }
  }

  async inboxLoop() {
    while (this.running) {
      try {
        const message = await fetchJson(`/api/lan/inbox/${this.id}`);
        if (message.available) await this.onMessage?.(message);
      } catch (error) {
        this.onStatus?.('error', error);
      }
      await delay(180);
    }
  }

  async stop() {
    this.running = false;
    try { await fetchJson(`/api/lan/leave/${this.id}`, { method: 'POST', body: 'leave' }); } catch { /* best effort */ }
  }
}

async function fetchJson(path, options) {
  const response = await fetch(path, { cache: 'no-store', ...options });
  if (!response.ok) throw new Error(await response.text());
  return response.json();
}

function delay(milliseconds) {
  return new Promise(resolve => window.setTimeout(resolve, milliseconds));
}
