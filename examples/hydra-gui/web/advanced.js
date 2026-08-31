import {
  base64ToBytes,
  bytesToBase64,
  downloadBytes,
  hexToBytes,
  readFile,
} from './bytes.js';
import { STEGO_DESCRIPTIONS } from './stego-client.js';

export class AdvancedController {
  constructor({ client, stego, ui, state }) {
    this.client = client;
    this.stego = stego;
    this.ui = ui;
    this.state = state;
    this.profile = sessionStorage.getItem('hydra.gui.stego-profile') || 'off';
    this.modelStatus = {};
    this.bindConversationControls();
    this.bindIdentityControls();
    this.bindContactCardControls();
    this.bindLobbyControls();
    this.bindStorageControls();
    this.bindAnonymousAuth();
    this.bindHistoryAndDiagnostics();
    this.applyProfile(this.profile);
  }

  bindConversationControls() {
    const el = this.ui.el;
    el['packet-size-select'].value = String(this.client.packetSize());
    el['packet-size-select'].addEventListener('change', () => this.run(async () => {
      await this.client.setPacketSize(Number(el['packet-size-select'].value));
      this.ui.toast('Packet ceiling updated.');
      this.state.refresh();
    }));
    el['stego-profile'].value = this.profile;
    el['stego-profile'].addEventListener('change', () => this.setProfile(el['stego-profile'].value));
    el['ai-model-select'].addEventListener('change', () => this.run(async () => {
      if (el['ai-model-select'].value) await this.stego.selectModel(el['ai-model-select'].value);
      this.state.refresh();
    }));
    el['session-cadence'].addEventListener('change', () => this.run(async () => {
      const conversation = this.directConversation();
      await this.client.setSessionCadence(conversation.contactId, Number(el['session-cadence'].value));
      this.ui.toast('Fresh-session cadence updated.');
      this.state.refresh();
    }));
    el['refresh-session-button'].addEventListener('click', () => this.run(async () => {
      const conversation = this.directConversation();
      await this.state.refreshSession(conversation.contactId);
      this.ui.toast('Fresh authenticated session established.');
    }));
    el['close-session-button'].addEventListener('click', () => this.run(async () => {
      const conversation = this.directConversation();
      await this.client.closeSession(conversation.contactId);
      this.ui.toast('Session closed; LAN auto-connect will establish a new one.');
      this.state.refresh();
    }));
    el['save-contact-name'].addEventListener('click', () => this.run(async () => {
      const conversation = this.directConversation();
      await this.client.renameContact(conversation.contactId, el['contact-name-input'].value.trim());
      this.state.refresh();
    }));
    el['verify-contact-button'].addEventListener('click', () => this.run(async () => {
      const conversation = this.directConversation();
      const contact = this.client.contact(conversation.contactId);
      if (contact.verified) await this.client.unverifyContact(conversation.contactId);
      else await this.client.verifyContact(conversation.contactId);
      this.state.refresh();
    }));
    el['block-contact-button'].addEventListener('click', () => this.run(async () => {
      const conversation = this.directConversation();
      const contact = this.client.contact(conversation.contactId);
      if (contact.blocked) await this.client.unblockContact(conversation.contactId);
      else await this.client.blockContact(conversation.contactId);
      this.state.refresh();
    }));
    el['remove-contact-button'].addEventListener('click', () => this.run(async () => {
      const conversation = this.directConversation();
      await this.client.removeContact(conversation.contactId);
      this.state.select(undefined);
      this.state.refresh();
    }));
  }

  bindIdentityControls() {
    const el = this.ui.el;
    el['identity-select'].addEventListener('change', () => this.fillIdentityFields());
    el['create-identity-button'].addEventListener('click', () => this.run(async () => {
      const password = required(el['new-identity-password'].value, 'Choose a password for the new identity.');
      const id = await this.client.createIdentity(el['new-identity-label'].value.trim() || 'Demo identity', password);
      await this.client.switchIdentity(id, password);
      await this.state.identityChanged();
      this.ui.toast('Identity created and activated.');
    }));
    el['switch-identity-button'].addEventListener('click', () => this.run(async () => {
      await this.client.switchIdentity(this.selectedIdentity(), required(el['identity-manage-password'].value, 'Enter the selected identity password.'));
      await this.state.identityChanged();
      this.ui.toast('Active identity changed.');
    }));
    el['rename-identity-button'].addEventListener('click', () => this.run(async () => {
      await this.client.renameIdentity(this.selectedIdentity(), required(el['identity-manage-label'].value.trim(), 'Enter an identity name.'));
      this.state.refresh();
    }));
    el['lock-identity-button'].addEventListener('click', () => this.run(async () => {
      const id = this.selectedIdentity();
      const identity = this.client.identities().find(item => item.id === id);
      if (identity?.unlocked) await this.client.lockIdentity(id);
      else await this.client.unlockIdentity(id, required(el['identity-manage-password'].value, 'Enter the identity password to unlock it.'));
      this.state.refresh();
    }));
    el['delete-identity-button'].addEventListener('click', () => this.run(async () => {
      const id = this.selectedIdentity();
      await this.client.deleteIdentity(id, required(el['identity-manage-password'].value, 'Enter the identity password to delete it.'));
      await this.state.identityChanged();
      this.ui.toast('Identity deleted.');
    }));
    el['change-identity-password-button'].addEventListener('click', () => this.run(async () => {
      await this.client.changeIdentityPassword(
        this.selectedIdentity(),
        required(el['identity-old-password'].value, 'Enter the old password.'),
        required(el['identity-new-password'].value, 'Enter a new password.'),
      );
      this.ui.toast('Identity password changed.');
    }));
    el['export-identity-button'].addEventListener('click', () => this.run(async () => {
      const id = this.selectedIdentity();
      const bytes = this.client.exportIdentity(id, required(el['identity-manage-password'].value, 'Enter the identity password to export it.'));
      downloadBytes(`hydra-identity-${id.slice(0, 8)}.bin`, bytes);
    }));
    el['import-identity-input'].addEventListener('change', () => this.run(async () => {
      const password = prompt('Password for the imported identity:');
      if (!password) return;
      const id = await this.client.importIdentity(await readFile(el['import-identity-input']), password, 'Imported identity');
      await this.client.switchIdentity(id, password);
      await this.state.identityChanged();
      el['import-identity-input'].value = '';
    }));
  }

  bindContactCardControls() {
    const el = this.ui.el;
    el['copy-contact-card-button'].addEventListener('click', () => this.run(() => this.copyBytes(this.client.createContactCard(), 'Default contact card copied.')));
    el['copy-labeled-contact-card-button'].addEventListener('click', () => this.run(() => this.copyBytes(
      this.client.createLabeledContactCard(required(el['contact-card-label'].value.trim(), 'Enter a public label first.')),
      'Labeled contact card copied.',
    )));
    el['copy-contact-invite-button'].addEventListener('click', () => this.run(() => this.copyBytes(this.client.createContactInvite(), 'Contact invite copied.')));
    el['one-time-contact-button'].addEventListener('click', () => this.run(async () => {
      const password = prompt('Password for the new one-time identity:');
      if (!password) return;
      const result = await this.client.createOneTimeContact(password);
      await navigator.clipboard.writeText(bytesToBase64(hexToBytes(result.cardHex)));
      await this.state.identityChanged();
      this.ui.toast('One-time contact card copied; its fresh identity is now active.');
    }));
    el['preview-contact-card-button'].addEventListener('click', () => this.run(async () => {
      const preview = this.client.previewContactCard(base64ToBytes(required(el['manual-contact-card'].value, 'Paste a base64 contact card.')));
      showResult(el['contact-card-preview'], preview);
    }));
    el['add-contact-card-button'].addEventListener('click', () => this.run(async () => {
      await this.client.addContact(base64ToBytes(required(el['manual-contact-card'].value, 'Paste a base64 contact card.')));
      this.ui.toast('Contact added.');
      this.state.refresh();
    }));
    el['export-contacts-button'].addEventListener('click', () => this.run(async () => downloadBytes('hydra-contacts.bin', this.client.exportContacts())));
    el['import-contacts-input'].addEventListener('change', () => this.run(async () => {
      await this.client.importContacts(await readFile(el['import-contacts-input']));
      el['import-contacts-input'].value = '';
      this.state.refresh();
    }));
  }

  bindLobbyControls() {
    const el = this.ui.el;
    el['create-lobby-button'].addEventListener('click', () => this.run(async () => {
      await this.state.createGroup(el['new-lobby-name'].value.trim() || 'Local group', Number(el['new-lobby-max'].value), this.client.contactIds());
    }));
    el['one-time-lobby-button'].addEventListener('click', () => this.run(async () => {
      const result = await this.client.oneTimeLobby(Number(el['new-lobby-max'].value));
      const invite = result.inviteHex ?? result.invite ?? result.cardHex;
      el['manual-lobby-invite'].value = invite || JSON.stringify(result);
      this.ui.toast('One-time lobby invite created.');
      this.state.refresh();
    }));
    el['preview-lobby-invite-button'].addEventListener('click', () => this.run(async () => {
      showResult(el['lobby-preview'], this.client.previewLobbyInvite(hexToBytes(required(el['manual-lobby-invite'].value, 'Paste a hex lobby invite.'))));
    }));
    el['join-lobby-button'].addEventListener('click', () => this.run(async () => {
      const id = await this.client.joinLobby(hexToBytes(required(el['manual-lobby-invite'].value, 'Paste a hex lobby invite.')));
      this.state.select(`lobby:${id}`);
      this.state.refresh();
    }));
    el['lobby-add-member-button'].addEventListener('click', () => this.run(async () => {
      const lobby = this.lobbyConversation();
      const contactId = required(el['lobby-add-member'].value, 'Choose a contact to add.');
      await this.client.addLobbyMember(lobby.lobbyId, contactId);
      await this.state.shareLobbyInvite(lobby.lobbyId, [contactId]);
      this.state.refresh();
    }));
    el['copy-lobby-invite'].addEventListener('click', () => this.run(async () => {
      const lobby = this.lobbyConversation();
      const invite = this.client.lobbyInvite(lobby.lobbyId, el['lobby-invite-style'].value);
      await navigator.clipboard.writeText(toHex(invite));
      this.ui.toast('Lobby invite copied as hex.');
    }));
    el['leave-lobby-button'].addEventListener('click', () => this.run(async () => {
      const lobby = this.lobbyConversation();
      await this.client.leaveLobby(lobby.lobbyId);
      this.state.select(undefined);
      this.state.refresh();
    }));
    el['close-lobby-button'].addEventListener('click', () => this.run(async () => {
      const lobby = this.lobbyConversation();
      await this.client.closeLobby(lobby.lobbyId);
      this.state.select(undefined);
      this.state.refresh();
    }));
  }

  bindStorageControls() {
    const el = this.ui.el;
    el['export-backup-button'].addEventListener('click', () => this.run(async () => downloadBytes('hydra-backup.bin', this.client.exportBackup(required(el['backup-password'].value, 'Enter a backup password.')))));
    el['verify-backup-input'].addEventListener('change', () => this.run(async () => {
      this.client.verifyBackup(await readFile(el['verify-backup-input']), required(el['backup-password'].value, 'Enter the backup password.'));
      el['verify-backup-input'].value = '';
      this.ui.toast('Backup verified without changing state.');
    }));
    el['import-backup-input'].addEventListener('change', () => this.run(async () => {
      await this.client.importBackup(await readFile(el['import-backup-input']), required(el['backup-password'].value, 'Enter the backup password.'));
      el['import-backup-input'].value = '';
      await this.state.identityChanged();
      this.ui.toast('Backup restored.');
    }));
    el['change-state-password-button'].addEventListener('click', () => this.run(async () => {
      await this.client.changeStatePassword(required(el['old-state-password'].value, 'Enter the current state password.'), required(el['new-state-password'].value, 'Enter a new state password.'));
      this.ui.toast('Encrypted-state password changed.');
    }));
    el['use-persistent-state-button'].addEventListener('click', () => this.run(async () => {
      await this.client.useStorageMode('persistent');
      location.reload();
    }));
    el['use-ephemeral-state-button'].addEventListener('click', () => this.run(async () => {
      await this.client.useStorageMode('ephemeral');
      location.reload();
    }));
    el['reset-persistent-state-button'].addEventListener('click', () => this.run(async () => {
      if (!window.confirm('Delete this tab\'s saved HYDRA demo profile? Exported backups are not affected.')) return;
      await this.client.resetPersistentProfile();
      location.reload();
    }));
    el['persistent-storage-button'].addEventListener('click', () => this.run(async () => showResult(el['storage-result'], { persistentGranted: await this.client.requestPersistentStorage() })));
    el['storage-status-button'].addEventListener('click', () => this.run(async () => showResult(el['storage-result'], this.client.storageStatus())));
    el['lifecycle-status-button'].addEventListener('click', () => this.run(async () => showResult(el['storage-result'], await this.client.lifecycleStatus())));
  }

  bindAnonymousAuth() {
    const el = this.ui.el;
    const token = () => base64ToBytes(required(el['auth-token'].value, 'Issue or paste a token first.'));
    const scope = () => required(el['auth-scope'].value.trim(), 'Enter an authorization scope.');
    const action = () => required(el['auth-action'].value.trim(), 'Enter an authorization action.');
    el['issue-auth-button'].addEventListener('click', () => this.run(async () => {
      const expiry = el['auth-expiry'].value ? Number(el['auth-expiry'].value) : undefined;
      el['auth-token'].value = bytesToBase64(await this.client.issueAnonymousAuth(scope(), action(), expiry));
      showResult(el['auth-result'], { issued: true, expiry: expiry ?? null });
    }));
    el['auth-nullifier-button'].addEventListener('click', () => this.run(async () => showResult(el['auth-result'], { nullifier: await this.client.anonymousAuthNullifier(token()) })));
    el['accept-auth-button'].addEventListener('click', () => this.run(async () => showResult(el['auth-result'], await this.client.acceptAnonymousAuth(token(), scope(), action(), Math.floor(Date.now() / 1000)))));
    el['revoke-auth-button'].addEventListener('click', () => this.run(async () => showResult(el['auth-result'], { revokedNullifier: await this.client.revokeAnonymousAuth(token(), scope(), action()) })));
  }

  bindHistoryAndDiagnostics() {
    const el = this.ui.el;
    el['export-messages-button'].addEventListener('click', () => this.run(async () => downloadBytes('hydra-message-history.bin', this.client.exportMessages())));
    el['import-messages-input'].addEventListener('change', () => this.run(async () => {
      await this.client.importMessages(await readFile(el['import-messages-input']));
      el['import-messages-input'].value = '';
      this.state.refresh();
    }));
    el['clear-messages-button'].addEventListener('click', () => this.run(async () => {
      const conversation = this.directConversation();
      await this.client.clearMessages(conversation.contactId);
      await this.state.clearVisibleHistory(conversation.key);
      this.state.refresh();
    }));
    el['benchmark-button'].addEventListener('click', () => this.run(async () => showResult(el['diagnostics-result'], await this.client.benchmark())));
    el['debug-status-button'].addEventListener('click', () => this.run(async () => showResult(el['diagnostics-result'], this.client.storageDebugStatus())));
  }

  async initializeModels() {
    const catalog = await this.stego.initialize();
    const select = this.ui.el['ai-model-select'];
    const recommended = catalog.recommendedModelId;
    select.replaceChildren(new Option('Choose local model…', ''), ...(catalog.models ?? []).map(model => new Option(`${model.label ?? model.name ?? model.id}${model.id === recommended ? ' · recommended' : ''}`, model.id)));
    await this.stego.refreshStatus();
  }

  onModelStatus(status) {
    this.modelStatus = status;
    const el = this.ui.el;
    el['ai-model-progress'].hidden = !status.loading;
    el['ai-model-progress'].value = Number(status.progress ?? 0);
    if (status.modelId && [...el['ai-model-select'].options].some(option => option.value === status.modelId)) el['ai-model-select'].value = status.modelId;
    el['ai-model-status'].textContent = status.error ? `Model error: ${status.error}` : status.ready ? `Ready · ${status.label ?? status.modelId ?? 'local model'}` : status.loading ? `${status.phase ?? 'Loading'} · ${Math.round(status.progress ?? 0)}%` : 'Choose a local model when an AI stego profile is selected.';
    this.state.refreshSendReadiness();
  }

  refresh(conversation) {
    const el = this.ui.el;
    el['packet-size-select'].value = String(this.client.packetSize());
    this.applyProfile(this.profile);
    el['stego-profile'].disabled = false;
    const identities = this.client.identities();
    this.ui.renderIdentityList(identities, this.client.activeId());
    if (!el['old-state-password'].value) el['old-state-password'].value = this.client.statePassword;
    el['storage-mode-label'].textContent = this.client.isPersistent()
      ? `Persistent IndexedDB · rev ${this.client.persistentRevision() ?? 0}`
      : 'Session-only memory';
    this.fillIdentityFields();
    const contacts = this.client.contacts();
    this.ui.renderContactLists(contacts);
    if (conversation?.type === 'direct') {
      const contact = this.client.contact(conversation.contactId);
      el['contact-name-input'].value = contact.label || '';
      el['advanced-safety-code'].textContent = contact.safetyCode || this.client.safetyCode(conversation.contactId);
      el['advanced-session-status'].textContent = this.client.sessionStatus(conversation.contactId);
      el['verify-contact-button'].textContent = contact.verified ? 'Mark unverified' : 'Verify safety code';
      el['block-contact-button'].textContent = contact.blocked ? 'Unblock' : 'Block';
      const security = this.client.sessionSecurity(conversation.contactId);
      el['session-cadence'].value = String(security.max_outbound_messages_per_session ?? 0);
    }
    if (conversation?.type === 'lobby') {
      const members = this.client.lobbyMembers(conversation.lobbyId);
      this.ui.renderLobbyMembers(contacts, members, id => this.run(async () => {
        await this.client.removeLobbyMember(conversation.lobbyId, id);
        this.state.refresh();
      }));
    }
  }

  applyProfile(profile) {
    const el = this.ui.el;
    el['stego-profile'].value = profile;
    el['stego-description'].textContent = STEGO_DESCRIPTIONS[profile] ?? STEGO_DESCRIPTIONS.off;
    el['ai-model-control'].hidden = !this.stego.requiresModel(profile);
  }

  setProfile(profile) {
    if (!(profile in STEGO_DESCRIPTIONS)) throw new Error(`Unknown stego profile: ${profile}`);
    this.profile = profile;
    sessionStorage.setItem('hydra.gui.stego-profile', profile);
    this.applyProfile(profile);
    this.state.refreshSendReadiness();
  }

  canSendStego() { return this.stego.readyFor(this.profile); }
  selectedProfile() { return this.profile; }

  fillIdentityFields() {
    const id = this.ui.el['identity-select'].value;
    const identity = this.client.identities().find(item => item.id === id);
    if (identity) {
      this.ui.el['identity-manage-label'].value = identity.label || '';
      const known = this.client.knownIdentityPassword(id);
      if (known) this.ui.el['identity-manage-password'].value = known;
    }
  }

  selectedIdentity() { return required(this.ui.el['identity-select'].value, 'Choose an identity.'); }
  directConversation() {
    const value = this.state.selected();
    if (!value || value.type !== 'direct') throw new Error('Select a direct conversation first.');
    return value;
  }
  lobbyConversation() {
    const value = this.state.selected();
    if (!value || value.type !== 'lobby') throw new Error('Select a group first.');
    return value;
  }

  async copyBytes(bytes, message) {
    await navigator.clipboard.writeText(bytesToBase64(bytes));
    this.ui.toast(message);
  }

  async run(task) {
    try {
      await this.client.whenIdle();
      await task();
    } catch (error) {
      this.ui.toast(cleanError(error), 'error');
    }
  }
}

function required(value, message) {
  if (!String(value ?? '').trim()) throw new Error(message);
  return value;
}

function showResult(node, value) {
  node.hidden = false;
  node.textContent = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
}

function toHex(bytes) {
  return [...bytes].map(value => value.toString(16).padStart(2, '0')).join('');
}

function cleanError(error) {
  return String(error?.message ?? error).replace(/^Error:\s*/, '');
}
