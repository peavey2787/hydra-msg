import { jsArray, randomHex, randomPassword } from './bytes.js';

const STATE_KEY = 'hydra.gui.state-password';
const IDENTITY_KEY = 'hydra.gui.identity-password';
const IDENTITY_PASSWORDS_KEY = 'hydra.gui.identity-passwords';
const PROFILE_KEY = 'hydra.gui.profile-name';
const STORAGE_MODE_KEY = 'hydra.gui.storage-mode';

export class HydraClient {
  constructor() {
    this.wasm = undefined;
    this.hydra = undefined;
    this.profileName = sessionStorage.getItem(PROFILE_KEY) || `hydra-gui-${randomHex(8)}`;
    sessionStorage.setItem(PROFILE_KEY, this.profileName);
    this.statePassword = sessionStorage.getItem(STATE_KEY) || randomPassword();
    this.identityPassword = sessionStorage.getItem(IDENTITY_KEY) || randomPassword();
    sessionStorage.setItem(STATE_KEY, this.statePassword);
    sessionStorage.setItem(IDENTITY_KEY, this.identityPassword);
    this.identityPasswords = loadPasswords();
    this.storageMode = sessionStorage.getItem(STORAGE_MODE_KEY) || 'persistent';
    this.operationTail = Promise.resolve();
    this.pendingOperations = 0;
  }

  async initialize() {
    this.wasm = await import('/pkg/hydra_msg_wasm.js');
    await this.wasm.default();
    const proto = this.wasm.WasmHydra?.prototype;
    if (typeof proto?.acceptHandshakeFinish !== 'function' || typeof proto?.acceptSessionRefreshFinish !== 'function' || typeof proto?.flushAndStateFreshnessAnchor !== 'function' || typeof proto?.verifyStateFreshnessAnchor !== 'function') {
      throw new Error('Stale HYDRA WASM package: rebuild it with examples/hydra-gui/scripts/build-wasm before starting this protocol version.');
    }
    this.hydra = this.storageMode === 'ephemeral'
      ? this.wasm.WasmHydra.openEphemeral(this.profileName, this.statePassword)
      : await this.wasm.WasmHydra.openPersistent(this.profileName, this.statePassword);
    await this.ensureIdentity();
    return this.summary();
  }

  async ensureIdentity() {
    return this.runExclusive(async () => {
      const ids = jsArray(this.hydra.listIds()).map(String);
      let active = this.hydra.activeId();
      if (!ids.length) {
        active = this.hydra.generateId(this.identityPassword);
        this.hydra.renameId(active, 'Local user');
        this.hydra.setActiveId(active, this.identityPassword);
        this.rememberIdentityPassword(this.identityPassword, active);
      } else {
        active ||= ids[0];
        try {
          const password = this.knownIdentityPassword(active) || this.identityPassword;
          this.hydra.setActiveId(active, password);
          this.rememberIdentityPassword(password, active);
        } catch (error) {
          throw new Error(`Saved identity could not be unlocked with this browser's demo password: ${error}`);
        }
      }
      await this.flushUnlocked();
      return active;
    });
  }

  isBusy() { return this.pendingOperations > 0; }
  whenIdle() { return this.operationTail.then(() => undefined, () => undefined); }

  runExclusive(task) {
    this.pendingOperations += 1;
    const run = this.operationTail.then(task, task);
    this.operationTail = run.then(
      value => { this.pendingOperations -= 1; return value; },
      error => { this.pendingOperations -= 1; throw error; },
    );
    this.operationTail = this.operationTail.catch(() => undefined);
    return run;
  }

  async flushUnlocked() {
    if (this.hydra?.isDirty()) await this.hydra.flush();
  }

  flush() { return this.runExclusive(() => this.flushUnlocked()); }

  activeId() { return this.hydra.activeId(); }
  packetSize() { return this.hydra.packetSize(); }
  setPacketSize(bytes) { return this.runExclusive(async () => { this.hydra.setPacketSize(Number(bytes)); await this.flushUnlocked(); }); }
  createContactCard() { return new Uint8Array(this.hydra.createContactCard()); }
  createLabeledContactCard(label) { return new Uint8Array(this.hydra.createLabeledContactCard(label)); }
  createContactInvite() { return new Uint8Array(this.hydra.createContactInvite()); }
  previewContactCard(bytes) { return JSON.parse(this.hydra.previewContactCard(bytes)); }

  async addContact(bytes, label) {
    return this.runExclusive(async () => {
      const id = this.hydra.addContact(bytes);
      if (label) this.hydra.renameContact(id, label);
      await this.flushUnlocked();
      return this.contact(id);
    });
  }

  contact(id) { return JSON.parse(this.hydra.getContact(id)); }
  contactIds() { return jsArray(this.hydra.listContacts()).map(String); }
  contacts() { return this.contactIds().map(id => this.contact(id)); }
  safetyCode(id) { return this.hydra.contactSafetyCode(id); }

  async verifyContact(id) { return this.runExclusive(async () => { this.hydra.verifyContact(id, this.safetyCode(id)); await this.flushUnlocked(); }); }
  async unverifyContact(id) { return this.runExclusive(async () => { this.hydra.unverifyContact(id); await this.flushUnlocked(); }); }
  async renameContact(id, label) { return this.runExclusive(async () => { this.hydra.renameContact(id, label); await this.flushUnlocked(); }); }
  async blockContact(id) { return this.runExclusive(async () => { this.hydra.blockContact(id); await this.flushUnlocked(); }); }
  async unblockContact(id) { return this.runExclusive(async () => { this.hydra.unblockContact(id); await this.flushUnlocked(); }); }
  async removeContact(id) { return this.runExclusive(async () => { this.hydra.removeContact(id); await this.flushUnlocked(); }); }

  sessionStatus(id) { return this.hydra.sessionStatus(id); }
  sessionSecurity(id) { return JSON.parse(this.hydra.sessionSecurityStatus(id)); }
  async handshakeOffer(id) { return this.runExclusive(async () => { const value = new Uint8Array(this.hydra.initHandshake(id)); await this.flushUnlocked(); return value; }); }
  async handshakeAnswer(offer) { return this.runExclusive(async () => { const value = new Uint8Array(this.hydra.replyHandshake(offer)); await this.flushUnlocked(); return value; }); }
  async finishHandshake(answer) { return this.runExclusive(async () => { const value = new Uint8Array(this.hydra.finishHandshake(answer)); await this.flushUnlocked(); return value; }); }
  async acceptHandshakeFinish(finish) { return this.runExclusive(async () => { this.hydra.acceptHandshakeFinish(finish); await this.flushUnlocked(); }); }
  async refreshOffer(id) { return this.runExclusive(async () => { const value = new Uint8Array(this.hydra.beginSessionRefresh(id)); await this.flushUnlocked(); return value; }); }
  async refreshAnswer(offer) { return this.runExclusive(async () => { const value = new Uint8Array(this.hydra.replySessionRefresh(offer)); await this.flushUnlocked(); return value; }); }
  async finishRefresh(answer) { return this.runExclusive(async () => { const value = new Uint8Array(this.hydra.finishSessionRefresh(answer)); await this.flushUnlocked(); return value; }); }
  async acceptRefreshFinish(finish) { return this.runExclusive(async () => { this.hydra.acceptSessionRefreshFinish(finish); await this.flushUnlocked(); }); }
  async setSessionCadence(id, count) { return this.runExclusive(async () => { this.hydra.setSessionRefreshInterval(id, Number(count)); await this.flushUnlocked(); }); }
  async closeSession(id) { return this.runExclusive(async () => { this.hydra.closeSession(id); await this.flushUnlocked(); }); }

  buildMessage(text, attachments = []) {
    let message = this.wasm.WasmHydraMessage.text(text);
    for (const attachment of attachments) message = message.attachFile(attachment.name, attachment.bytes);
    return message;
  }

  async send(id, text, attachments = []) {
    return this.runExclusive(async () => {
      const packets = jsArray(this.hydra.send(id, this.buildMessage(text, attachments)))
        .map(packet => new Uint8Array(packet));
      await this.flushUnlocked();
      return packets;
    });
  }

  async sendCompactText(id, text) {
    return this.runExclusive(async () => {
      const packet = new Uint8Array(this.hydra.sendCompactText(id, text));
      await this.flushUnlocked();
      return packet;
    });
  }

  async receive(packet) {
    return this.runExclusive(async () => {
      const received = this.hydra.receive(packet);
      await this.flushUnlocked();
      return received || null;
    });
  }

  async receiveCompact(packet) {
    return this.runExclusive(async () => {
      const received = this.hydra.receiveCompact(packet);
      await this.flushUnlocked();
      return received;
    });
  }

  receivedMessage(received) {
    const attachments = [];
    for (let index = 0; index < received.attachmentCount(); index += 1) {
      attachments.push({
        name: received.attachmentFilename(index),
        bytes: new Uint8Array(received.attachmentBytes(index)),
      });
    }
    let text;
    try { text = received.text(); } catch { text = `[${received.plaintext().length} bytes]`; }
    return {
      from: received.from(),
      id: received.messageId(),
      lobbyId: received.lobbyId(),
      text,
      attachments,
    };
  }

  messageIds(contactId) { return jsArray(this.hydra.listMessages(contactId)).map(wasmU64); }
  getMessage(id) { return this.receivedMessage(this.hydra.getMessage(wasmU64(id))); }
  async deleteMessage(id) { return this.runExclusive(async () => { this.hydra.deleteMessage(wasmU64(id)); await this.flushUnlocked(); }); }
  async clearMessages(contactId) { return this.runExclusive(async () => { this.hydra.clearMessages(contactId); await this.flushUnlocked(); }); }
  exportMessages() { return new Uint8Array(this.hydra.exportMessages()); }
  async importMessages(bytes) { return this.runExclusive(async () => { this.hydra.importMessages(bytes); await this.flushUnlocked(); }); }

  async createLobby(label, maxMembers) {
    return this.runExclusive(async () => {
      const id = this.hydra.createLobby(label, Number(maxMembers));
      await this.flushUnlocked();
      return id;
    });
  }
  lobbyIds() { return jsArray(this.hydra.listLobbies()).map(String); }
  lobby(id) { return JSON.parse(this.hydra.getLobby(id)); }
  lobbies() { return this.lobbyIds().map(id => this.lobby(id)); }
  lobbyMembers(id) { return jsArray(this.hydra.lobbyMembers(id)).map(String); }
  async addLobbyMember(lobbyId, contactId) { return this.runExclusive(async () => { this.hydra.addLobbyMember(lobbyId, contactId); await this.flushUnlocked(); }); }
  async removeLobbyMember(lobbyId, contactId) { return this.runExclusive(async () => { this.hydra.removeLobbyMember(lobbyId, contactId); await this.flushUnlocked(); }); }
  lobbyInvite(id, style = 'minimal') {
    const fn = style === 'labeled' ? 'createLabeledLobbyInvite' : style === 'members' ? 'createLobbyMemberInvite' : 'createLobbyInvite';
    return new Uint8Array(this.hydra[fn](id));
  }
  previewLobbyInvite(bytes) { return JSON.parse(this.hydra.previewLobbyInvite(bytes)); }
  async joinLobby(bytes) { return this.runExclusive(async () => { const id = this.hydra.joinLobby(bytes); await this.flushUnlocked(); return id; }); }
  async leaveLobby(id) { return this.runExclusive(async () => { this.hydra.leaveLobby(id); await this.flushUnlocked(); }); }
  async closeLobby(id) { return this.runExclusive(async () => { this.hydra.closeLobby(id); await this.flushUnlocked(); }); }
  async oneTimeLobby(maxMembers) { return this.runExclusive(async () => { const result = JSON.parse(this.hydra.createOneTimeLobbyInvite(Number(maxMembers))); await this.flushUnlocked(); return result; }); }
  async sendLobby(id, text, attachments = []) {
    return this.runExclusive(async () => {
      const values = jsArray(this.hydra.sendLobby(id, this.buildMessage(text, attachments)));
      await this.flushUnlocked();
      return values.map(value => ({
        recipient: value.recipient(),
        routingHint: value.routingHintHex(),
        packet: new Uint8Array(value.envelope()),
      }));
    });
  }
  async receiveLobby(packet) { return this.runExclusive(async () => { const value = this.hydra.receiveLobby(packet); await this.flushUnlocked(); return value || null; }); }

  identities() {
    return jsArray(this.hydra.listIds()).map(String).map(id => JSON.parse(this.hydra.getId(id)));
  }
  async createIdentity(label, password) {
    return this.runExclusive(async () => {
      const id = this.hydra.generateId(password);
      this.hydra.renameId(id, label);
      this.rememberIdentityPassword(password, id);
      await this.flushUnlocked();
      return id;
    });
  }
  async switchIdentity(id, password) { return this.runExclusive(async () => { this.hydra.setActiveId(id, password); this.rememberIdentityPassword(password, id); await this.flushUnlocked(); }); }
  exportIdentity(id, password) { return new Uint8Array(this.hydra.exportId(id, password)); }
  async importIdentity(bytes, password, label) {
    return this.runExclusive(async () => {
      const id = this.hydra.importId(bytes, password);
      if (label) this.hydra.renameId(id, label);
      this.rememberIdentityPassword(password, id);
      await this.flushUnlocked();
      return id;
    });
  }
  async lockIdentity(id) { return this.runExclusive(async () => { this.hydra.lockId(id); await this.flushUnlocked(); }); }
  async unlockIdentity(id, password) { return this.runExclusive(async () => { this.hydra.unlockId(id, password); await this.flushUnlocked(); }); }
  async renameIdentity(id, label) { return this.runExclusive(async () => { this.hydra.renameId(id, label); await this.flushUnlocked(); }); }
  async changeIdentityPassword(id, oldPassword, newPassword) { return this.runExclusive(async () => { this.hydra.changeIdPassword(id, oldPassword, newPassword); this.rememberIdentityPassword(newPassword, id); await this.flushUnlocked(); }); }
  async deleteIdentity(id, password) { return this.runExclusive(async () => { this.hydra.deleteId(id, password); delete this.identityPasswords[id]; this.persistIdentityPasswords(); await this.flushUnlocked(); }); }
  async createOneTimeContact(password) {
    return this.runExclusive(async () => {
      const result = JSON.parse(this.hydra.createOneTimeContactCard(password));
      this.rememberIdentityPassword(password, result.identityId);
      await this.flushUnlocked();
      return result;
    });
  }

  exportContacts() { return new Uint8Array(this.hydra.exportContacts()); }
  async importContacts(bytes) { return this.runExclusive(async () => { this.hydra.importContacts(bytes); await this.flushUnlocked(); }); }
  exportBackup(password) { return new Uint8Array(this.hydra.exportBackup(password)); }
  verifyBackup(bytes, password) { this.hydra.verifyBackup(bytes, password); }
  async importBackup(bytes, password) { return this.runExclusive(async () => { this.hydra.importBackup(bytes, password); await this.flushUnlocked(); }); }
  async changeStatePassword(oldPassword, newPassword) { return this.runExclusive(async () => { this.hydra.changeStatePassword(oldPassword, newPassword); this.statePassword = newPassword; sessionStorage.setItem(STATE_KEY, newPassword); await this.flushUnlocked(); }); }
  storageStatus() { return JSON.parse(this.hydra.storageStatus()); }
  storageDebugStatus() { return JSON.parse(this.hydra.storageDebugStatus()); }
  async requestPersistentStorage() { return this.wasm.WasmHydra.requestPersistentStorage(); }
  async lifecycleStatus() { return JSON.parse(await this.wasm.WasmHydra.browserLifecycleStatus()); }
  isPersistent() { return this.hydra.isPersistent(); }
  persistentRevision() { return this.hydra.persistentRevision(); }
  async useStorageMode(mode) {
    if (!['persistent', 'ephemeral'].includes(mode)) throw new Error('Unknown browser storage mode.');
    sessionStorage.setItem(STORAGE_MODE_KEY, mode);
  }
  async resetPersistentProfile() {
    await this.wasm.WasmHydra.deletePersistent(this.profileName);
  }
  async benchmark() { return this.runExclusive(async () => { const report = this.hydra.benchmark(); return JSON.parse(report.toJson()); }); }

  async issueAnonymousAuth(scope, action, expiry) {
    if (typeof this.hydra.issueAnonymousAuthToken === 'function') {
      return this.runExclusive(async () => { const token = new Uint8Array(this.hydra.issueAnonymousAuthToken(scope, action, expiry ?? undefined)); await this.flushUnlocked(); return token; });
    }
    return this.authRequest(`/api/auth/issue/${encodeURIComponent(scope)}/${encodeURIComponent(action)}/${expiry ?? 'none'}`);
  }

  async anonymousAuthNullifier(token) {
    if (typeof this.hydra.anonymousAuthNullifier === 'function') return this.runExclusive(async () => this.hydra.anonymousAuthNullifier(token));
    return new TextDecoder().decode(await this.authRequest('/api/auth/nullifier', token));
  }

  async acceptAnonymousAuth(token, scope, action, now) {
    if (typeof this.hydra.acceptAnonymousAuthToken === 'function') {
      return this.runExclusive(async () => { const result = JSON.parse(this.hydra.acceptAnonymousAuthToken(token, scope, action, now)); await this.flushUnlocked(); return result; });
    }
    return JSON.parse(new TextDecoder().decode(await this.authRequest(
      `/api/auth/accept/${encodeURIComponent(scope)}/${encodeURIComponent(action)}/${now}`, token,
    )));
  }

  async revokeAnonymousAuth(token, scope, action) {
    if (typeof this.hydra.revokeAnonymousAuthToken === 'function') {
      return this.runExclusive(async () => { const result = this.hydra.revokeAnonymousAuthToken(token, scope, action); await this.flushUnlocked(); return result; });
    }
    return new TextDecoder().decode(await this.authRequest(
      `/api/auth/revoke/${encodeURIComponent(scope)}/${encodeURIComponent(action)}`, token,
    ));
  }

  async authRequest(path, body) {
    const response = await fetch(path, { method: 'POST', body });
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (!response.ok) throw new Error(new TextDecoder().decode(bytes) || `Anonymous authorization request failed (${response.status}).`);
    return bytes;
  }

  knownIdentityPassword(id) { return this.identityPasswords[id]; }

  rememberIdentityPassword(password, id = this.activeId()) {
    this.identityPassword = password;
    sessionStorage.setItem(IDENTITY_KEY, password);
    if (id) {
      this.identityPasswords[id] = password;
      this.persistIdentityPasswords();
    }
  }

  persistIdentityPasswords() {
    sessionStorage.setItem(IDENTITY_PASSWORDS_KEY, JSON.stringify(this.identityPasswords));
  }

  summary() {
    return {
      activeId: this.activeId(),
      identities: this.identities(),
      contacts: this.contacts(),
      lobbies: this.lobbies(),
      storage: this.storageStatus(),
    };
  }
}

function wasmU64(value) {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) throw new Error(`Invalid HYDRA message id: ${value}`);
    return BigInt(value);
  }
  if (typeof value === 'string' && /^[0-9]+$/.test(value)) return BigInt(value);
  throw new Error(`Invalid HYDRA message id: ${String(value)}`);
}

function loadPasswords() {
  try { return JSON.parse(sessionStorage.getItem(IDENTITY_PASSWORDS_KEY) || '{}'); } catch { return {}; }
}
