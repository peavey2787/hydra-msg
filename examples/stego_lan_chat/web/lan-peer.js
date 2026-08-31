export class LanPeer {
  constructor(onMessage, onStatus) {
    this.onMessage = onMessage;
    this.onStatus = onStatus;
    this.connection = null;
    this.channel = null;
    this.initiator = false;
    this.outboundSequence = 0;
    this.inboundMessages = new Map();
  }

  async createOffer() {
    this.initiator = true;
    this.connection = this.createConnection();
    this.attachChannel(this.connection.createDataChannel('hydra-stego'));
    await this.connection.setLocalDescription(await this.connection.createOffer());
    await waitForIce(this.connection);
    return encodeDescription(this.connection.localDescription);
  }

  async createAnswer(encodedOffer) {
    this.initiator = false;
    this.connection = this.createConnection();
    await this.connection.setRemoteDescription(decodeDescription(encodedOffer));
    await this.connection.setLocalDescription(await this.connection.createAnswer());
    await waitForIce(this.connection);
    return encodeDescription(this.connection.localDescription);
  }

  async acceptAnswer(encodedAnswer) {
    if (!this.connection || !this.initiator) throw new Error('Create an offer first.');
    await this.connection.setRemoteDescription(decodeDescription(encodedAnswer));
  }

  send(message) {
    if (!this.channel || this.channel.readyState !== 'open') {
      throw new Error('The WebRTC DataChannel is not open.');
    }
    const serialized = JSON.stringify(message);
    const messageId = `${this.initiator ? 'offer' : 'answer'}-${this.outboundSequence}`;
    this.outboundSequence += 1;
    const total = Math.ceil(serialized.length / CHUNK_CHARACTERS);
    for (let index = 0; index < total; index += 1) {
      this.channel.send(JSON.stringify({
        hydraCarrierChunk: 1,
        messageId,
        index,
        total,
        data: serialized.slice(index * CHUNK_CHARACTERS, (index + 1) * CHUNK_CHARACTERS),
      }));
    }
  }

  isOpen() {
    return this.channel?.readyState === 'open';
  }

  createConnection() {
    const connection = new RTCPeerConnection({ iceServers: [] });
    connection.ondatachannel = event => this.attachChannel(event.channel);
    connection.oniceconnectionstatechange = () => {
      this.onStatus(`${connection.iceConnectionState} / ${this.channel?.readyState ?? 'no channel'}`);
    };
    return connection;
  }

  attachChannel(channel) {
    this.channel = channel;
    channel.onopen = () => this.onStatus('connected', true);
    channel.onclose = () => this.onStatus('closed');
    channel.onerror = () => this.onStatus('channel error');
    channel.onmessage = event => {
      try {
        this.acceptChunk(JSON.parse(event.data));
      } catch (error) {
        this.onStatus(`carrier error: ${error}`);
      }
    };
  }

  acceptChunk(chunk) {
    if (
      chunk.hydraCarrierChunk !== 1
      || typeof chunk.messageId !== 'string'
      || chunk.messageId.length > 64
      || !Number.isInteger(chunk.index)
      || !Number.isInteger(chunk.total)
      || chunk.index < 0
      || chunk.total < 1
      || chunk.index >= chunk.total
      || chunk.total > MAX_CHUNKS
      || typeof chunk.data !== 'string'
      || chunk.data.length > CHUNK_CHARACTERS
    ) {
      throw new Error('Malformed WebRTC carrier chunk.');
    }

    let pending = this.inboundMessages.get(chunk.messageId);
    if (!pending) {
      if (this.inboundMessages.size >= MAX_PENDING_MESSAGES) {
        this.inboundMessages.delete(this.inboundMessages.keys().next().value);
      }
      pending = { total: chunk.total, parts: new Map() };
      this.inboundMessages.set(chunk.messageId, pending);
    }
    if (pending.total !== chunk.total) throw new Error('Conflicting WebRTC carrier chunks.');
    const existing = pending.parts.get(chunk.index);
    if (existing !== undefined && existing !== chunk.data) {
      throw new Error('Conflicting duplicate WebRTC carrier chunk.');
    }
    pending.parts.set(chunk.index, chunk.data);
    if (pending.parts.size !== pending.total) return;

    const parts = [];
    for (let index = 0; index < pending.total; index += 1) {
      const part = pending.parts.get(index);
      if (part === undefined) return;
      parts.push(part);
    }
    this.inboundMessages.delete(chunk.messageId);
    this.onMessage(JSON.parse(parts.join('')));
  }
}

const CHUNK_CHARACTERS = 16 * 1024;
const MAX_CHUNKS = 4096;
const MAX_PENDING_MESSAGES = 32;

async function waitForIce(connection) {
  if (connection.iceGatheringState === 'complete') return;
  await new Promise((resolve, reject) => {
    const timeout = window.setTimeout(() => {
      connection.removeEventListener('icegatheringstatechange', check);
      reject(new Error('Timed out while gathering LAN WebRTC candidates.'));
    }, 15_000);
    const check = () => {
      if (connection.iceGatheringState === 'complete') {
        connection.removeEventListener('icegatheringstatechange', check);
        window.clearTimeout(timeout);
        resolve();
      }
    };
    connection.addEventListener('icegatheringstatechange', check);
  });
}

function encodeDescription(description) {
  return btoa(JSON.stringify(description));
}

function decodeDescription(encoded) {
  return JSON.parse(atob(encoded.trim()));
}
