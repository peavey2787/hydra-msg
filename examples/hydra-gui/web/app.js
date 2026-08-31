import { AdvancedController } from './advanced.js';
import { base64ToBytes } from './bytes.js';
import { decodeControl, decodeGroupText, encodeControl, encodeGroupText, isGroupText, newMessageKey, newRequestId } from './message-protocol.js';
import { HydraClient } from './hydra-client.js';
import { LanClient } from './lan-client.js';
import { MessageViewStore } from './message-view-store.js';
import { StegoClient } from './stego-client.js';
import { UI } from './ui.js';

const HANDSHAKE_RESPONSE_TIMEOUT_MS = 3_000;
const HANDSHAKE_RETRY_DELAYS_MS = [600, 1_200, 2_400, 4_800];
const HANDSHAKE_RETRY_COOLDOWN_MS = 10_000;

class HydraGuiApp {
  constructor() {
    this.ui = new UI();
    this.client = new HydraClient();
    this.stego = new StegoClient(status => this.advanced?.onModelStatus(status));
    this.lan = new LanClient({
      onPeers: peers => this.queuePeerSync(peers),
      onMessage: message => this.handleLanMessage(message),
      onStatus: (state, error) => this.onLanStatus(state, error),
    });
    this.peerByLan = new Map();
    this.lanByContact = new Map();
    this.pendingHandshakes = new Map();
    this.pendingHandshakeFinishes = new Map();
    this.handshakeRetryAfter = new Map();
    this.pendingRefreshes = new Map();
    this.refreshWaiters = new Map();
    this.messages = new Map();
    this.messageViewStore = new MessageViewStore();
    this.seenStoredMessages = new Set();
    this.attachments = [];
    this.selectedKey = undefined;
    this.privacyMode = sessionStorage.getItem('hydra.gui.privacy-mask') === '1';
    this.carrierRevealAll = sessionStorage.getItem('hydra.gui.carrier-reveal-all') === '1';
    if (this.privacyMode && this.carrierRevealAll) {
      this.carrierRevealAll = false;
      sessionStorage.setItem('hydra.gui.carrier-reveal-all', '0');
    }
    this.pendingRemovalRequests = new Map();
    this.refreshQueued = false;
    this.peerSync = Promise.resolve();
  }

  async start() {
    try {
      this.ui.setLanStatus('pending', 'Loading encrypted browser state');
      await this.client.initialize();
      this.advanced = new AdvancedController({
        client: this.client,
        stego: this.stego,
        ui: this.ui,
        state: this.advancedState(),
      });
      this.bindChatControls();
      await this.advanced.initializeModels().catch(error => this.ui.toast(`AI model catalog unavailable: ${cleanError(error)}`, 'error'));
      await this.hydrateHistory();
      await this.lan.start(this.client.createContactCard());
      this.ui.ready();
      this.refresh();
    } catch (error) {
      this.ui.ready();
      this.ui.setLanStatus('bad', cleanError(error));
      this.ui.toast(`Startup failed: ${cleanError(error)}`, 'error');
    }
  }

  advancedState() {
    return {
      selected: () => this.selectedConversation(),
      select: key => this.select(key),
      refresh: () => this.refresh(),
      refreshSession: id => this.refreshSession(id),
      identityChanged: () => this.identityChanged(),
      createGroup: (label, max, contacts) => this.createGroup(label, max, contacts),
      shareLobbyInvite: (lobbyId, contacts) => this.shareLobbyInvite(lobbyId, contacts),
      clearVisibleHistory: key => this.clearVisibleHistory(key),
      refreshSendReadiness: () => this.refreshSendReadiness(),
    };
  }

  bindChatControls() {
    const el = this.ui.el;
    el['conversation-search'].addEventListener('input', () => this.refresh());
    el['attachment-input'].addEventListener('change', () => this.addAttachments(el['attachment-input']));
    el['message-composer'].addEventListener('submit', event => {
      event.preventDefault();
      void this.sendSelected();
    });
    el['message-input'].addEventListener('keydown', event => {
      if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        el['message-composer'].requestSubmit();
      }
    });
    el['message-input'].addEventListener('input', () => this.syncPrivacyInputMask());
    el['message-input'].addEventListener('scroll', () => this.syncPrivacyInputMask());
    el['privacy-toggle'].addEventListener('click', () => this.setPrivacyMode(!this.privacyMode));
    el['carrier-view-toggle'].addEventListener('click', () => this.setCarrierRevealAll(!this.carrierRevealAll));
    el['quick-create-group'].addEventListener('click', () => void this.quickCreateGroup());
    for (const id of ['advanced-button', 'header-advanced-button', 'settings-button']) {
      el[id].addEventListener('click', () => queueMicrotask(() => this.refresh()));
    }
    this.ui.setPrivacyMode(this.privacyMode);
    this.ui.setCarrierRevealAll(this.carrierRevealAll);
    this.syncPrivacyInputMask();
    window.addEventListener('beforeunload', () => void this.lan.stop());
  }

  async addAttachments(input) {
    const files = [...(input.files ?? [])];
    for (const file of files) this.attachments.push({ name: file.name, bytes: new Uint8Array(await file.arrayBuffer()) });
    input.value = '';
    this.renderPendingAttachments();
  }

  renderPendingAttachments() {
    this.ui.renderPendingAttachments(this.attachments, index => {
      this.attachments.splice(index, 1);
      this.renderPendingAttachments();
      this.refreshSendReadiness();
    });
    this.refreshSendReadiness();
  }

  queuePeerSync(peers) {
    this.peerSync = this.peerSync.then(() => this.syncPeers(peers)).catch(error => this.ui.toast(`Peer discovery: ${cleanError(error)}`, 'error'));
  }

  async syncPeers(peers) {
    await this.client.whenIdle();
    let changed = false;
    const available = new Set(peers.map(peer => peer.id));
    for (const record of this.peerByLan.values()) {
      const nextAvailable = available.has(record.lanId);
      if (record.available !== nextAvailable) changed = true;
      record.available = nextAvailable;
      if (!nextAvailable) {
        this.cancelHandshake(record.contactId);
        this.cancelHandshakeFinish(record.contactId);
      }
    }
    for (const peer of peers) {
      const card = base64ToBytes(peer.card);
      const preview = this.client.previewContactCard(card);
      let contact;
      try {
        contact = this.client.contact(preview.id);
      } catch {
        contact = await this.client.addContact(card, preview.label || `LAN peer ${peer.id.slice(0, 6)}`);
      }
      if (!contact.verified && !contact.blocked) {
        await this.client.verifyContact(contact.id);
        contact = this.client.contact(contact.id);
      }
      const record = {
        lanId: peer.id,
        contactId: contact.id,
        available: true,
        title: contact.label || preview.label || `LAN peer ${peer.id.slice(0, 6)}`,
      };
      const prior = this.peerByLan.get(peer.id);
      if (!prior || prior.contactId !== record.contactId || prior.title !== record.title || !prior.available) changed = true;
      this.peerByLan.set(peer.id, record);
      this.lanByContact.set(contact.id, peer.id);
      if (!contact.blocked) await this.ensureSession(record);
    }
    if (changed) this.refresh();
  }

  async ensureSession(peer) {
    const status = this.client.sessionStatus(peer.contactId);
    if (status === 'Active') {
      this.cancelHandshake(peer.contactId);
      this.handshakeRetryAfter.delete(peer.contactId);
      return;
    }
    if (this.pendingHandshakes.has(peer.contactId) || this.lan.id > peer.lanId) return;
    if ((this.handshakeRetryAfter.get(peer.contactId) ?? 0) > Date.now()) return;
    const offer = await this.client.handshakeOffer(peer.contactId);
    const state = { peerId: peer.lanId, offer, attempt: 0, token: undefined, timer: undefined };
    this.pendingHandshakes.set(peer.contactId, state);
    await this.sendHandshakeAttempt(peer.contactId, state);
  }

  async sendHandshakeAttempt(contactId, state) {
    if (this.pendingHandshakes.get(contactId) !== state) return;
    await this.client.whenIdle();
    if (this.pendingHandshakes.get(contactId) !== state) return;
    const peer = this.peerByLan.get(state.peerId);
    if (!peer?.available || this.client.sessionStatus(contactId) === 'Active') {
      this.cancelHandshake(contactId);
      return;
    }
    state.attempt += 1;
    state.token = newRequestId();
    clearTimeout(state.timer);
    try {
      await this.lan.send(state.peerId, 'handshake-offer', state.offer, state.token);
    } catch (error) {
      this.scheduleHandshakeRetry(contactId, state);
      return;
    }
    state.timer = window.setTimeout(() => {
      if (this.pendingHandshakes.get(contactId)?.token !== state.token) return;
      this.scheduleHandshakeRetry(contactId, state);
    }, HANDSHAKE_RESPONSE_TIMEOUT_MS);
  }

  scheduleHandshakeRetry(contactId, state) {
    if (this.pendingHandshakes.get(contactId) !== state) return;
    clearTimeout(state.timer);
    const delay = HANDSHAKE_RETRY_DELAYS_MS[state.attempt - 1];
    if (delay === undefined) {
      this.pendingHandshakes.delete(contactId);
      this.handshakeRetryAfter.set(contactId, Date.now() + HANDSHAKE_RETRY_COOLDOWN_MS);
      this.ui.toast('Secure session is taking longer than expected; HYDRA will keep retrying automatically.');
      return;
    }
    state.timer = window.setTimeout(() => void this.sendHandshakeAttempt(contactId, state), delay);
  }

  cancelHandshake(contactId) {
    const state = this.pendingHandshakes.get(contactId);
    if (state?.timer) clearTimeout(state.timer);
    this.pendingHandshakes.delete(contactId);
  }

  cancelAllHandshakes() {
    for (const contactId of [...this.pendingHandshakes.keys()]) this.cancelHandshake(contactId);
    for (const contactId of [...this.pendingHandshakeFinishes.keys()]) this.cancelHandshakeFinish(contactId);
    this.handshakeRetryAfter.clear();
  }

  async handleLanMessage(message) {
    try {
      const payload = base64ToBytes(message.payload);
      if (message.kind === 'handshake-offer') return await this.answerHandshake(message.from, payload, message.tag);
      if (message.kind === 'handshake-answer') return await this.finishHandshake(message.from, payload, message.tag);
      if (message.kind === 'handshake-finish') return await this.acceptHandshakeFinish(message.from, payload, message.tag);
      if (message.kind === 'handshake-complete') return this.completeHandshake(message.from, message.tag);
      if (message.kind === 'refresh-offer') return await this.answerRefresh(message.from, payload);
      if (message.kind === 'refresh-answer') return await this.finishRefresh(message.from, payload);
      if (message.kind === 'refresh-finish') return await this.acceptRefreshFinish(message.from, payload);
      if (message.kind === 'delete-request') return await this.receiveDeleteRequest(message.from, decodeControl(payload));
      if (message.kind === 'delete-response') return this.receiveDeleteResponse(decodeControl(payload));
      if (message.kind === 'direct-packet') return await this.receiveDirect(payload, message.tag || newMessageKey());
      if (message.kind === 'lobby-packet') return await this.receiveLobby(payload, message.tag || newMessageKey());
      if (message.kind === 'lobby-invite') return await this.receiveLobbyInvite(payload);
      if (message.kind.startsWith('stego-group-')) return await this.receiveGroupStego(message.kind.slice(12), payload, message.tag || newMessageKey());
      if (message.kind.startsWith('stego-')) return await this.receiveStego(message.kind.slice(6), payload, message.tag || newMessageKey());
    } catch (error) {
      this.ui.toast(`Incoming ${message.kind}: ${cleanError(error)}`, 'error');
    } finally {
      this.refresh();
    }
  }

  async answerHandshake(peerId, offer, attemptToken) {
    const answer = await this.client.handshakeAnswer(offer);
    await this.lan.send(peerId, 'handshake-answer', answer, attemptToken);
  }

  async finishHandshake(peerId, answer, attemptToken) {
    const record = this.peerByLan.get(peerId);
    const contactId = record?.contactId ?? [...this.pendingHandshakes].find(([, state]) => state.peerId === peerId)?.[0];
    const state = contactId ? this.pendingHandshakes.get(contactId) : undefined;
    if (!state || !attemptToken || state.token !== attemptToken) return;
    const finish = await this.client.finishHandshake(answer);
    this.cancelHandshake(contactId);
    const finishState = { peerId, finish, token: attemptToken, attempt: 0, timer: undefined };
    this.pendingHandshakeFinishes.set(contactId, finishState);
    await this.sendHandshakeFinishAttempt(contactId, finishState);
    this.handshakeRetryAfter.delete(contactId);
    this.ui.toast('Authenticated HYDRA session established; confirming peer receipt.');
  }

  async sendHandshakeFinishAttempt(contactId, state) {
    if (this.pendingHandshakeFinishes.get(contactId) !== state) return;
    const peer = this.peerByLan.get(state.peerId);
    if (!peer?.available) {
      this.cancelHandshakeFinish(contactId);
      return;
    }
    state.attempt += 1;
    clearTimeout(state.timer);
    try {
      await this.lan.send(state.peerId, 'handshake-finish', state.finish, state.token);
    } catch {
      this.scheduleHandshakeFinishRetry(contactId, state);
      return;
    }
    state.timer = window.setTimeout(() => this.scheduleHandshakeFinishRetry(contactId, state), HANDSHAKE_RESPONSE_TIMEOUT_MS);
  }

  scheduleHandshakeFinishRetry(contactId, state) {
    if (this.pendingHandshakeFinishes.get(contactId) !== state) return;
    clearTimeout(state.timer);
    const delay = HANDSHAKE_RETRY_DELAYS_MS[state.attempt - 1];
    if (delay === undefined) {
      this.cancelHandshakeFinish(contactId);
      void this.recoverFromUnconfirmedFinish(contactId);
      return;
    }
    state.timer = window.setTimeout(() => void this.sendHandshakeFinishAttempt(contactId, state), delay);
  }

  cancelHandshakeFinish(contactId) {
    const state = this.pendingHandshakeFinishes.get(contactId);
    if (state?.timer) clearTimeout(state.timer);
    this.pendingHandshakeFinishes.delete(contactId);
  }

  async recoverFromUnconfirmedFinish(contactId) {
    try {
      await this.client.closeSession(contactId);
    } catch {}
    this.handshakeRetryAfter.set(contactId, Date.now() + HANDSHAKE_RETRY_DELAYS_MS[0]);
    this.ui.toast('Peer FINISH acknowledgement was not received; starting a fresh session handshake.', 'error');
    this.refresh();
  }

  async acceptHandshakeFinish(peerId, finish, attemptToken) {
    await this.client.acceptHandshakeFinish(finish);
    await this.lan.send(peerId, 'handshake-complete', new Uint8Array(), attemptToken);
    const record = this.peerByLan.get(peerId);
    if (record) this.handshakeRetryAfter.delete(record.contactId);
    this.ui.toast('Authenticated HYDRA session established.');
  }

  completeHandshake(peerId, attemptToken) {
    const record = this.peerByLan.get(peerId);
    if (!record) return;
    const state = this.pendingHandshakeFinishes.get(record.contactId);
    if (!state || state.peerId !== peerId || state.token !== attemptToken) return;
    this.cancelHandshakeFinish(record.contactId);
  }

  async refreshSession(contactId) {
    const existing = this.refreshWaiters.get(contactId);
    if (existing) return existing.promise;
    const peerId = this.lanByContact.get(contactId);
    if (!peerId) throw new Error('That contact is not currently available through LAN discovery.');

    let resolveRefresh;
    let rejectRefresh;
    const promise = new Promise((resolve, reject) => {
      resolveRefresh = resolve;
      rejectRefresh = reject;
    });
    const timeout = setTimeout(() => {
      if (!this.refreshWaiters.has(contactId)) return;
      this.pendingRefreshes.delete(contactId);
      this.refreshWaiters.delete(contactId);
      rejectRefresh(new Error('Session refresh timed out. The peer may have gone offline.'));
      this.refresh();
    }, 12_000);
    this.pendingRefreshes.set(contactId, peerId);
    this.refreshWaiters.set(contactId, { promise, resolve: resolveRefresh, reject: rejectRefresh, timeout });
    try {
      await this.lan.send(peerId, 'refresh-offer', await this.client.refreshOffer(contactId));
    } catch (error) {
      this.failRefresh(contactId, error);
    }
    return promise;
  }

  async answerRefresh(peerId, offer) {
    await this.lan.send(peerId, 'refresh-answer', await this.client.refreshAnswer(offer));
  }

  async finishRefresh(peerId, answer) {
    const finish = await this.client.finishRefresh(answer);
    await this.lan.send(peerId, 'refresh-finish', finish);
    for (const [contactId, lanId] of [...this.pendingRefreshes]) {
      if (lanId !== peerId) continue;
      this.pendingRefreshes.delete(contactId);
      const waiter = this.refreshWaiters.get(contactId);
      if (waiter) {
        clearTimeout(waiter.timeout);
        this.refreshWaiters.delete(contactId);
        waiter.resolve();
      }
    }
    this.refresh();
  }

  async acceptRefreshFinish(_peerId, finish) {
    await this.client.acceptRefreshFinish(finish);
    this.refresh();
  }

  failRefresh(contactId, error) {
    this.pendingRefreshes.delete(contactId);
    const waiter = this.refreshWaiters.get(contactId);
    if (!waiter) return;
    clearTimeout(waiter.timeout);
    this.refreshWaiters.delete(contactId);
    waiter.reject(error);
  }

  async ensureFreshSession(contactId) {
    if (this.client.sessionSecurity(contactId).refresh_required) {
      this.ui.setSending(true, 'Refreshing session…');
      await this.refreshSession(contactId);
      this.ui.setSending(true, 'Encrypting…');
    }
  }

  async sendSelected() {
    await this.client.whenIdle();
    const conversation = this.selectedConversation();
    if (!conversation) return;
    const text = this.ui.el['message-input'].value.trim();
    if (!text && !this.attachments.length) return;
    this.ui.setSending(true, 'Encrypting…');
    try {
      if (conversation.type === 'direct') await this.sendDirect(conversation, text);
      else await this.sendGroup(conversation, text);
      this.clearDraft();
      this.attachments = [];
      this.renderPendingAttachments();
    } catch (error) {
      this.ui.toast(`Send failed: ${cleanError(error)}`, 'error');
    } finally {
      this.ui.setSending(false);
      this.refresh();
    }
  }

  async sendDirect(conversation, text) {
    const peerId = this.lanByContact.get(conversation.contactId);
    if (!peerId) throw new Error('Peer is offline.');
    await this.ensureFreshSession(conversation.contactId);
    const profile = this.advanced.selectedProfile();
    const messageKey = newMessageKey();
    const canUseStego = profile !== 'off' && this.attachments.length === 0 && text.length > 0;
    let carrier;
    if (canUseStego) {
      if (!this.advanced.canSendStego()) throw new Error('Choose and load the AI cover model for this stego profile first.');
      this.ui.setSending(true, 'Creating stego carrier…');
      carrier = await this.stego.encode(profile, await this.client.sendCompactText(conversation.contactId, text));
      await this.lan.send(peerId, `stego-${profile}`, carrier, messageKey);
    } else {
      if (profile !== 'off' && this.attachments.length) this.ui.toast('Attachments use HYDRA padded packets; stego remains selected for text-only messages.');
      const packets = await this.client.send(conversation.contactId, text, this.attachments);
      for (const packet of packets) await this.lan.send(peerId, 'direct-packet', packet, messageKey);
    }
    await this.appendMessage(conversation.key, {
      direction: 'outgoing', text: text || 'Attachment', attachments: cloneAttachments(this.attachments),
      time: nowTime(), delivery: 'encrypted',
      carrier, stegoProfile: canUseStego ? profile : undefined, messageKey,
    });
  }

  async sendGroup(conversation, text) {
    const messageKey = newMessageKey();
    const members = this.client.lobbyMembers(conversation.lobbyId);
    const offline = members.filter(contactId => !this.lanByContact.has(contactId));
    if (offline.length) throw new Error(`Group send paused: ${offline.length} member${offline.length === 1 ? ' is' : 's are'} offline.`);
    for (const contactId of members) await this.ensureFreshSession(contactId);
    const profile = this.advanced.selectedProfile();
    const canUseStego = profile !== 'off' && this.attachments.length === 0 && text.length > 0;
    let carrier;
    let delivered = 0;
    if (canUseStego) {
      if (!this.advanced.canSendStego()) throw new Error('Choose and load the AI cover model for this stego profile first.');
      this.ui.setSending(true, 'Creating group carriers…');
      const wrappedText = encodeGroupText(conversation.lobbyId, text);
      for (const contactId of members) {
        const peerId = this.lanByContact.get(contactId);
        if (!peerId) throw new Error('A group member went offline while the message was being sent.');
        const memberCarrier = await this.stego.encode(profile, await this.client.sendCompactText(contactId, wrappedText));
        carrier ??= memberCarrier;
        await this.lan.send(peerId, `stego-group-${profile}`, memberCarrier, messageKey);
        delivered += 1;
      }
    } else {
      if (profile !== 'off' && this.attachments.length) this.ui.toast('Attachments use HYDRA padded group packets; the selected text carrier remains active for text-only messages.');
      const envelopes = await this.client.sendLobby(conversation.lobbyId, text, this.attachments);
      for (const envelope of envelopes) {
        const peerId = this.lanByContact.get(envelope.recipient);
        if (!peerId) throw new Error('A group member went offline while the message was being sent.');
        await this.lan.send(peerId, 'lobby-packet', envelope.packet, messageKey);
        delivered += 1;
      }
    }
    await this.appendMessage(conversation.key, {
      direction: 'outgoing', text: text || 'Attachment', attachments: cloneAttachments(this.attachments),
      time: nowTime(), delivery: `encrypted · ${delivered} peer${delivered === 1 ? '' : 's'}`, messageKey,
      carrier, stegoProfile: canUseStego ? profile : undefined,
    });
  }

  async receiveDirect(packet, messageKey) {
    const received = await this.client.receive(packet);
    if (!received) return;
    await this.storeReceived(this.client.receivedMessage(received), messageKey);
  }

  async receiveStego(profile, encodedCover, messageKey) {
    await this.stego.refreshStatus();
    const cover = new TextDecoder().decode(encodedCover);
    const received = await this.client.receiveCompact(await this.stego.decode(profile, cover));
    const message = this.client.receivedMessage(received);
    message.carrier = cover;
    message.stegoProfile = profile;
    await this.storeReceived(message, messageKey);
  }

  async receiveLobby(packet, messageKey) {
    const received = await this.client.receiveLobby(packet);
    if (!received) return;
    await this.storeReceived(this.client.receivedMessage(received), messageKey);
  }

  async receiveGroupStego(profile, encodedCover, messageKey) {
    await this.stego.refreshStatus();
    const cover = new TextDecoder().decode(encodedCover);
    const received = await this.client.receiveCompact(await this.stego.decode(profile, cover));
    const message = this.client.receivedMessage(received);
    const grouped = decodeGroupText(message.text);
    if (!this.client.lobbyIds().includes(grouped.lobbyId)) throw new Error('Received a group carrier for an unknown lobby.');
    message.lobbyId = grouped.lobbyId;
    message.text = grouped.text;
    message.carrier = cover;
    message.stegoProfile = profile;
    await this.storeReceived(message, messageKey);
  }

  async storeReceived(message, messageKey) {
    const key = message.lobbyId ? `lobby:${message.lobbyId}` : `direct:${message.from}`;
    await this.appendMessage(key, {
      direction: 'incoming', text: message.text, attachments: message.attachments,
      time: nowTime(), delivery: 'decrypted',
      id: message.id, carrier: message.carrier, stegoProfile: message.stegoProfile, messageKey,
    });
    if (!this.selectedKey) this.select(key);
  }

  async receiveLobbyInvite(invite) {
    const preview = this.client.previewLobbyInvite(invite);
    let id = preview.id;
    if (!this.client.lobbyIds().includes(id)) id = await this.client.joinLobby(invite);
    this.appendMessage(`lobby:${id}`, { system: true, text: `Joined ${preview.label || 'a HYDRA group'} from an automatic LAN invite.` });
    if (!this.selectedKey) this.select(`lobby:${id}`);
  }

  async createGroup(label, maxMembers, contactIds) {
    const members = [...new Set(contactIds)].filter(id => this.lanByContact.has(id));
    const id = await this.client.createLobby(label, maxMembers);
    for (const contactId of members) await this.client.addLobbyMember(id, contactId);
    await this.shareLobbyInvite(id, members);
    this.appendMessage(`lobby:${id}`, { system: true, text: 'Group created. HYDRA member invite shared with online peers.' });
    this.select(`lobby:${id}`);
    this.ui.el['group-dialog'].close();
    this.ui.el['settings-dialog'].close();
    this.refresh();
    return id;
  }

  async shareLobbyInvite(lobbyId, contactIds) {
    const invite = this.client.lobbyInvite(lobbyId, 'members');
    for (const contactId of contactIds) {
      const peerId = this.lanByContact.get(contactId);
      if (peerId) await this.lan.send(peerId, 'lobby-invite', invite);
    }
  }

  async quickCreateGroup() {
    try {
      const contacts = [...this.ui.el['quick-group-members'].querySelectorAll('input:checked')].map(input => input.value);
      await this.createGroup(this.ui.el['quick-group-name'].value.trim() || 'Local group', Math.max(2, contacts.length + 1), contacts);
    } catch (error) {
      this.ui.toast(cleanError(error), 'error');
    }
  }

  async identityChanged() {
    await this.client.ensureIdentity();
    this.peerByLan.clear();
    this.lanByContact.clear();
    this.cancelAllHandshakes();
    this.pendingRefreshes.clear();
    for (const [contactId] of this.refreshWaiters) this.failRefresh(contactId, new Error('Identity changed during session refresh.'));
    await this.lan.updateCard(this.client.createContactCard());
    this.selectedKey = undefined;
    await this.hydrateHistory();
    this.refresh();
  }

  async hydrateHistory() {
    this.messages.clear();
    this.seenStoredMessages.clear();
    if (this.client.isPersistent()) {
      try {
        for (const record of await this.messageViewStore.load(this.historyScope())) {
          await this.appendMessage(record.conversationKey, record.message, { persist: false, render: false });
          if (record.message.id !== undefined && record.message.id !== null) this.seenStoredMessages.add(String(record.message.id));
        }
      } catch (error) {
        this.ui.toast(`Saved carrier views unavailable: ${cleanError(error)}`, 'error');
      }
    }
    for (const contact of this.client.contacts()) {
      for (const id of this.client.messageIds(contact.id)) {
        const marker = String(id);
        if (this.seenStoredMessages.has(marker)) continue;
        const message = this.client.getMessage(id);
        this.seenStoredMessages.add(marker);
        if (!message.lobbyId && isGroupText(message.text)) {
          const grouped = decodeGroupText(message.text);
          message.lobbyId = grouped.lobbyId;
          message.text = grouped.text;
        }
        const key = message.lobbyId ? `lobby:${message.lobbyId}` : `direct:${contact.id}`;
        await this.appendMessage(key, {
          direction: 'incoming', text: message.text, attachments: message.attachments,
          time: '', delivery: 'stored', id: message.id, messageKey: `stored-${message.id}`,
        }, { render: false });
      }
    }
  }

  conversations() {
    const contacts = this.client.contacts().map(contact => {
      const peerId = this.lanByContact.get(contact.id);
      const peer = peerId ? this.peerByLan.get(peerId) : undefined;
      const ready = !contact.blocked && peer?.available && this.client.sessionStatus(contact.id) === 'Active';
      const handshake = this.pendingHandshakes.get(contact.id);
      const retrying = Boolean(handshake && handshake.attempt > 1);
      const coolingDown = !handshake && (this.handshakeRetryAfter.get(contact.id) ?? 0) > Date.now();
      return {
        key: `direct:${contact.id}`, type: 'direct', contactId: contact.id,
        title: contact.label || `Peer ${contact.id.slice(0, 8)}`,
        subtitle: contact.blocked ? 'Blocked' : peer?.available ? ready ? 'LAN peer · encrypted session ready' : retrying || coolingDown ? 'LAN peer · retrying secure session' : 'LAN peer · establishing secure session' : 'Saved contact · offline',
        meta: ready ? 'secure' : peer?.available ? retrying || coolingDown ? 'retrying' : 'linking' : '', ready,
      };
    });
    const lobbies = this.client.lobbies().map(lobby => ({
      key: `lobby:${lobby.id}`, type: 'lobby', lobbyId: lobby.id,
      title: lobby.label || 'HYDRA group', subtitle: `${lobby.memberCount} of ${lobby.maxMembers} members`,
      memberCount: lobby.memberCount, ready: true, meta: 'group',
    }));
    return [...contacts, ...lobbies];
  }

  selectedConversation() {
    return this.conversations().find(item => item.key === this.selectedKey);
  }

  select(key) {
    this.selectedKey = typeof key === 'string' ? key : key?.key;
    for (const messages of this.messages.values()) {
      for (const message of messages) {
        const hasCarrier = Boolean(message.carrier && message.stegoProfile);
        message.privacyRevealed = Boolean(this.privacyMode && hasCarrier && this.carrierRevealAll);
        if (hasCarrier) message.stegoView = this.carrierRevealAll ? 'decoded' : 'carrier';
      }
    }
    this.refresh();
  }

  refresh() {
    if (this.client.isBusy()) {
      if (!this.refreshQueued) {
        this.refreshQueued = true;
        void this.client.whenIdle().then(() => {
          this.refreshQueued = false;
          this.refresh();
        });
      }
      return;
    }
    const conversations = this.conversations();
    if (this.selectedKey && !conversations.some(item => item.key === this.selectedKey)) this.selectedKey = undefined;
    const selected = conversations.find(item => item.key === this.selectedKey);
    this.ui.renderConversations(conversations, this.selectedKey, item => this.select(item.key));
    this.ui.setConversation(selected);
    this.ui.setWelcomeProgress(this.peerByLan.size > 0, conversations.some(item => item.type === 'direct' && item.ready));
    this.ui.renderQuickGroupMembers(conversations.filter(item => item.type === 'direct' && this.lanByContact.has(item.contactId)));
    if (!this.ui.el['advanced-drawer'].hidden || this.ui.el['settings-dialog'].open) this.advanced?.refresh(selected);
    this.renderSelectedMessages();
    this.refreshSendReadiness();
  }

  renderSelectedMessages(options = {}) {
    const messages = this.messages.get(this.selectedKey) ?? [];
    this.ui.renderMessages(messages, {
      privacyMode: this.privacyMode,
      preserveIndex: options.preserveIndex,
      preserveScroll: options.preserveScroll,
      onToggleMessage: index => {
        const message = messages[index];
        if (!message) return;
        if (this.privacyMode) {
          message.privacyRevealed = !message.privacyRevealed;
        } else if (message.carrier && message.stegoProfile) {
          message.stegoView = message.stegoView === 'decoded' ? 'carrier' : 'decoded';
        }
        return message;
      },
      onRemoveLocal: index => void this.removeMessageLocally(index).catch(error => this.ui.toast(cleanError(error), 'error')),
      onRequestRemoval: index => void this.requestMessageRemoval(index).catch(error => this.ui.toast(cleanError(error), 'error')),
      onRemovalDecision: (index, accepted) => void this.decideRemoval(index, accepted).catch(error => this.ui.toast(cleanError(error), 'error')),
    });
  }

  setPrivacyMode(enabled) {
    const next = Boolean(enabled);
    if (next === this.privacyMode) return;
    this.privacyMode = next;
    sessionStorage.setItem('hydra.gui.privacy-mask', next ? '1' : '0');
    if (next) {
      this.carrierRevealAll = false;
      sessionStorage.setItem('hydra.gui.carrier-reveal-all', '0');
      this.ui.setCarrierRevealAll(false);
    }
    for (const messages of this.messages.values()) {
      for (const message of messages) {
        message.privacyRevealed = false;
        if (message.carrier && message.stegoProfile) message.stegoView = this.carrierRevealAll ? 'decoded' : 'carrier';
      }
    }
    this.ui.setPrivacyMode(next);
    this.syncPrivacyInputMask();
    this.renderSelectedMessages({ preserveScroll: true });
    this.ui.el['message-input'].focus();
  }

  setCarrierRevealAll(enabled) {
    this.carrierRevealAll = Boolean(enabled);
    sessionStorage.setItem('hydra.gui.carrier-reveal-all', this.carrierRevealAll ? '1' : '0');
    for (const messages of this.messages.values()) {
      for (const message of messages) {
        if (!message.carrier || !message.stegoProfile) continue;
        message.stegoView = this.carrierRevealAll ? 'decoded' : 'carrier';
        if (this.privacyMode) message.privacyRevealed = this.carrierRevealAll;
      }
    }
    this.ui.setCarrierRevealAll(this.carrierRevealAll);
    this.renderSelectedMessages({ preserveScroll: true });
    this.ui.el['message-input'].focus();
  }

  syncPrivacyInputMask() {
    const input = this.ui.el['message-input'];
    const mask = this.ui.el['message-input-mask'];
    input.classList.toggle('privacy-input-active', this.privacyMode);
    mask.hidden = !this.privacyMode;
    mask.textContent = input.value.replace(/[^\s]/g, '*');
    mask.scrollTop = input.scrollTop;
    mask.scrollLeft = input.scrollLeft;
  }

  clearDraft() {
    this.ui.el['message-input'].value = '';
    this.syncPrivacyInputMask();
  }

  async removeMessageLocally(index) {
    const list = this.messages.get(this.selectedKey) ?? [];
    const message = list[index];
    if (!message) return;
    if (message.id !== undefined && message.id !== null) {
      try { await this.client.deleteMessage(message.id); } catch (error) { this.ui.toast(`Local removal: ${cleanError(error)}`, 'error'); return; }
    }
    list.splice(index, 1);
    if (this.client.isPersistent()) await this.messageViewStore.delete(this.historyScope(), this.selectedKey, message.messageKey);
    this.renderSelectedMessages({ preserveScroll: true });
  }

  async requestMessageRemoval(index) {
    await this.client.whenIdle();
    const conversation = this.selectedConversation();
    const list = this.messages.get(this.selectedKey) ?? [];
    const message = list[index];
    if (!conversation || !message) return;
    const peerIds = this.participantPeerIds(conversation);
    if (!peerIds.length) {
      this.ui.toast('No other participant is online to receive a removal request.', 'error');
      return;
    }
    const requestId = newRequestId();
    this.pendingRemovalRequests.set(requestId, { expected: peerIds.length, responses: 0, accepted: 0, kept: 0 });
    const control = encodeControl({ requestId, messageKey: message.messageKey });
    for (const peerId of peerIds) await this.lan.send(peerId, 'delete-request', control);
    await this.removeMessageLocally(index);
    this.ui.toast(`Removal requested from ${peerIds.length} participant${peerIds.length === 1 ? '' : 's'}. They decide independently.`);
  }

  participantPeerIds(conversation) {
    if (conversation.type === 'direct') {
      const peerId = this.lanByContact.get(conversation.contactId);
      return peerId ? [peerId] : [];
    }
    const contacts = this.client.lobbyMembers(conversation.lobbyId);
    const peerIds = contacts.map(id => this.lanByContact.get(id));
    if (peerIds.some(id => !id)) throw new Error('All group participants must be online before a remove-for-everyone request can be sent.');
    return [...new Set(peerIds)];
  }

  async receiveDeleteRequest(peerId, control) {
    const located = this.findMessage(control.messageKey);
    if (!located) {
      await this.lan.send(peerId, 'delete-response', encodeControl({ requestId: control.requestId, messageKey: control.messageKey, accepted: false, missing: true }));
      return;
    }
    located.message.removalRequest = { requestId: control.requestId, requesterLanId: peerId };
    if (located.key === this.selectedKey) this.renderSelectedMessages({ preserveScroll: true });
    this.ui.toast('A participant requested removal of one message. You can remove it or keep it.');
  }

  async decideRemoval(index, accepted) {
    const list = this.messages.get(this.selectedKey) ?? [];
    const message = list[index];
    const request = message?.removalRequest;
    if (!message || !request) return;
    const response = encodeControl({ requestId: request.requestId, messageKey: message.messageKey, accepted: Boolean(accepted) });
    if (accepted) {
      const peerId = request.requesterLanId;
      await this.removeMessageLocally(index);
      await this.lan.send(peerId, 'delete-response', response);
    } else {
      delete message.removalRequest;
      this.renderSelectedMessages({ preserveScroll: true });
      await this.lan.send(request.requesterLanId, 'delete-response', response);
    }
  }

  receiveDeleteResponse(control) {
    const state = this.pendingRemovalRequests.get(control.requestId);
    if (!state) return;
    state.responses += 1;
    if (control.accepted) state.accepted += 1;
    else state.kept += 1;
    this.ui.toast(control.accepted ? 'A participant accepted the removal request.' : 'A participant kept the message.');
    if (state.responses >= state.expected) {
      this.pendingRemovalRequests.delete(control.requestId);
      this.ui.toast(`Removal request complete: ${state.accepted} removed, ${state.kept} kept.`);
    }
  }

  findMessage(messageKey) {
    for (const [key, messages] of this.messages) {
      const index = messages.findIndex(message => message.messageKey === messageKey);
      if (index >= 0) return { key, index, message: messages[index] };
    }
    return undefined;
  }

  refreshSendReadiness() {
    if (this.client.isBusy()) {
      void this.client.whenIdle().then(() => this.refreshSendReadiness());
      return;
    }
    const selected = this.selectedConversation();
    let ready = Boolean(selected);
    const profile = this.advanced?.selectedProfile() ?? 'off';
    if (selected?.type === 'direct') {
      ready = selected.ready;
    } else if (selected?.type === 'lobby') {
      const members = this.client.lobbyMembers(selected.lobbyId);
      ready = members.length > 0 && members.every(contactId => this.lanByContact.has(contactId) && this.client.sessionStatus(contactId) === 'Active');
    }
    if (ready && profile !== 'off' && this.attachments.length === 0) ready &&= this.advanced.canSendStego();
    this.ui.setSessionReady(ready);
  }

  historyScope() {
    return `${this.client.profileName}:${this.client.activeId()}`;
  }

  async clearVisibleHistory(key) {
    this.messages.delete(key);
    if (this.client.isPersistent()) await this.messageViewStore.clearConversation(this.historyScope(), key);
  }

  async appendMessage(key, message, options = {}) {
    const { persist = true, render = true } = options;
    if (!this.messages.has(key)) this.messages.set(key, []);
    const list = this.messages.get(key);
    if (message.id !== undefined && message.id !== null && list.some(item => String(item.id) === String(message.id))) return;
    message.messageKey ||= newMessageKey();
    if (message.carrier && message.stegoProfile) {
      message.stegoView ||= this.carrierRevealAll ? 'decoded' : 'carrier';
      if (this.privacyMode && this.carrierRevealAll) message.privacyRevealed = true;
    }
    list.push(message);
    if (list.length > 500) list.splice(0, list.length - 500);
    if (render && key === this.selectedKey) this.renderSelectedMessages();
    if (persist && this.client.isPersistent()) {
      await this.messageViewStore.put(this.historyScope(), key, message).catch(error => this.ui.toast(`Message view save failed: ${cleanError(error)}`, 'error'));
    }
  }

  onLanStatus(state, error) {
    if (state === 'connected') this.ui.setLanStatus('ok', `${this.peerByLan.size} local peer${this.peerByLan.size === 1 ? '' : 's'} discovered`);
    else this.ui.setLanStatus('bad', cleanError(error || 'Retrying local rendezvous'));
  }
}

function cloneAttachments(items) {
  return items.map(item => ({ name: item.name, bytes: new Uint8Array(item.bytes) }));
}

function nowTime() {
  return new Intl.DateTimeFormat([], { hour: 'numeric', minute: '2-digit' }).format(new Date());
}

function cleanError(error) {
  return String(error?.message ?? error).replace(/^Error:\s*/, '');
}

void new HydraGuiApp().start();
