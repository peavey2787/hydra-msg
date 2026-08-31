import { downloadBytes } from './bytes.js';

const HELP = {
  hydra: ['HYDRA in this demo', '<p><strong>HYDRA</strong> owns identities, contact trust, authenticated hybrid handshakes, ratcheted encrypted sessions, attachments, lobbies, encrypted local state, backups, and replay protection.</p><p>The browser holds chat state. The local Rust host serves the app, discovers peers, relays opaque demo traffic, optionally runs the stego AI model, and hosts the separate anonymous-authorization demonstration issuer.</p>'],
  conversation: ['Conversation', '<p>A direct chat is tied to a HYDRA contact and authenticated session. A group chat is a HYDRA lobby with one encrypted copy per member.</p><p>Use <strong>Details</strong> for safety codes, session cadence, packet size, steganography, and contact/group administration.</p>'],
  autoconnect: ['Automatic LAN connection', '<p>Each browser publishes its HYDRA contact card to this demo host. Browsers discover cards, add the contact locally, verify the displayed safety code for demonstration purposes, and exchange HYDRA handshake bytes through the local relay.</p><p>This removes setup friction for the example. A real application should use an authenticated discovery and user-verification ceremony appropriate to its threat model.</p>'],
  delivery: ['Message carrier', '<p>The composer selector chooses how text crosses the demo relay: <strong>encrypted</strong>, <strong>stego-instant</strong>, <strong>stego-unicode</strong>, <strong>stego hybrid</strong>, or <strong>stego-ai</strong>.</p><p>For a group text, the demo creates one compact encrypted carrier per member. Attachments continue to use HYDRA padded lobby packets. Text carriers transform an already encrypted compact HYDRA envelope; they do not add encryption or anonymity.</p>'],
  'session-security': ['Session security', '<p>Every encrypted envelope advances HYDRA\'s one-way message ratchet. The optional cadence also forces a fresh authenticated hybrid session after a chosen number of outbound logical messages.</p><p><strong>Refresh now</strong> performs that peer round trip immediately. <strong>Close session</strong> removes the current session and automatic LAN setup can establish a new one.</p>'],
  stego: ['Text carriers', '<p><strong>encrypted</strong> is the normal padded HYDRA carrier. <strong>stego-instant</strong> needs no model; <strong>stego-unicode</strong>, <strong>stego hybrid</strong>, and <strong>stego-ai</strong> use the selected local AI model.</p><p>Carrier text is shown by default in the transcript and reveals decoded plaintext only when clicked. The carrier transformation is reversible but does not promise resistance to steganalysis.</p>'],
  privacy: ['Privacy mask', '<p>The <strong>***</strong> button is a local display-only privacy mode. While it is active, the composer keeps the real draft locally but renders only asterisks, and message bodies are masked with asterisks.</p><p>Click one message to reveal its decoded plaintext locally; click it again to mask it. While privacy mode is active, the <strong>S</strong> button toggles only steganographic messages between asterisks and decoded plaintext; ordinary messages stay masked. This does not change what is encrypted or sent to peers.</p>'],
  'carrier-view': ['Carrier message view', '<p>The <strong>S</strong> button changes only stego carrier messages. Carrier text remains the default private view; use this control to reveal all decoded carrier messages at once, then switch them all back to carrier text.</p><p>You can still click an individual carrier message to toggle only that message.</p>'],
  removal: ['Message removal', "<p><strong>Remove from this device</strong> deletes only this browser's copy. <strong>Request removal for everyone</strong> sends a consent request to every currently connected participant in that conversation.</p><p>No remote copy is deleted automatically. Each participant can remove it, keep it, or simply ignore the request.</p>"],
  'contact-trust': ['Contact trust', '<p>HYDRA derives a safety code from contact key material. Verification records that the code was checked out of band. This demo can auto-verify discovered peers to keep setup effortless, while still exposing the real safety code and verify/unverify controls.</p><p>Blocking prevents normal use of that contact until unblocked.</p>'],
  identity: ['Identities', '<p>An identity owns long-term HYDRA key material and is separately password protected inside the encrypted local state. You can create, rename, lock, unlock, export, import, switch, change passwords, and delete identities.</p><p>The demo creates one automatically on first run.</p>'],
  'contact-cards': ['Contact cards', '<p>Contact cards share public verification material. Default cards minimize metadata; labeled cards intentionally expose a label. One-time contact cards create a fresh identity for an unlinkable chat setup.</p><p>Preview validates a card without changing local state. Add persists it as a contact.</p>'],
  lobbies: ['Groups / lobbies', '<p>HYDRA lobbies create an encrypted copy of each message for each member. Invites can be minimized, labeled, include a member list, or be created as one-time lobby invites.</p><p>Routing hints are carrier helpers, not authentication. The encrypted envelope is still authoritative.</p>'],
  storage: ['Encrypted browser storage & backup', '<p>The browser can use HYDRA\'s authenticated encrypted state container in IndexedDB, or an explicit session-only in-memory profile for demonstrations. Mutations in persistent mode are flushed through the WASM persistence wrapper.</p><p>Backups are separately password-encrypted portable snapshots. Verify checks a backup without changing current state; restore replaces current state after validation.</p>'],
  'storage-mode': ['Persistent vs session-only state', '<p><strong>Persistent</strong> uses encrypted IndexedDB state and survives reloads. <strong>Session-only</strong> uses HYDRA\'s explicit ephemeral wrapper and starts fresh after reload.</p><p>Switching modes reloads this demo tab. Reset deletes this tab\'s saved IndexedDB profile but does not delete exported backups.</p>'],
  'anonymous-auth': ['Anonymous one-time authorization', '<p>This is HYDRA\'s bounded one-time bearer-token authorization flow. A token authorizes one scope/action pair and can optionally expire. Acceptance records a nullifier so the same token cannot be accepted twice by the same verifier.</p><p>This demo uses a separate HYDRA issuer on the local host so the feature works with the bundled browser package. It is not blind issuance and does not provide network anonymity by itself.</p>'],
  history: ['Message history', '<p>HYDRA stores received message records locally. The public facade can list, retrieve, delete, clear, export, and import message history without exposing protocol internals.</p>'],
  diagnostics: ['Diagnostics', '<p>Storage status gives a redacted production-style summary. Debug status includes local object counts for troubleshooting. The benchmark exercises local handshake and message operations to demonstrate expected device performance.</p>'],
};

export class UI {
  constructor() {
    this.el = Object.fromEntries([...document.querySelectorAll('[id]')].map(node => [node.id, node]));
    this.selectedKey = undefined;
    this.openMessageMenu = undefined;
    this.openMessageMenuButton = undefined;
    this.installMessageMenuDismissal();
    this.installHelp();
    this.installDrawerButtons();
  }


  installMessageMenuDismissal() {
    document.addEventListener('pointerdown', event => {
      if (!this.openMessageMenu) return;
      if (this.openMessageMenu.contains(event.target) || this.openMessageMenuButton?.contains(event.target)) return;
      this.closeMessageMenu();
    });
    document.addEventListener('keydown', event => {
      if (event.key === 'Escape') this.closeMessageMenu();
    });
    this.el['message-list']?.addEventListener('scroll', () => this.closeMessageMenu(), { passive: true });
  }

  closeMessageMenu() {
    if (this.openMessageMenu) this.openMessageMenu.hidden = true;
    if (this.openMessageMenuButton) this.openMessageMenuButton.setAttribute('aria-expanded', 'false');
    this.openMessageMenu = undefined;
    this.openMessageMenuButton = undefined;
  }

  toggleMessageMenu(menu, button) {
    const shouldOpen = menu.hidden;
    this.closeMessageMenu();
    if (!shouldOpen) return;
    menu.hidden = false;
    button.setAttribute('aria-expanded', 'true');
    this.openMessageMenu = menu;
    this.openMessageMenuButton = button;
  }

  installHelp() {
    document.querySelectorAll('.help-button[data-help]').forEach(button => {
      button.addEventListener('click', event => {
        event.preventDefault();
        event.stopPropagation();
        this.showHelp(button.dataset.help);
      });
    });
  }

  showHelp(topic) {
    const [title, body] = HELP[topic] ?? ['Help', '<p>No additional help is available.</p>'];
    this.el['help-title'].textContent = title;
    this.el['help-body'].innerHTML = body;
    this.el['help-dialog'].showModal();
  }

  installDrawerButtons() {
    const open = () => this.showAdvanced(true);
    this.el['advanced-button'].addEventListener('click', open);
    this.el['header-advanced-button'].addEventListener('click', open);
    this.el['close-advanced'].addEventListener('click', () => this.showAdvanced(false));
    this.el['settings-button'].addEventListener('click', () => this.el['settings-dialog'].showModal());
    this.el['new-group-button'].addEventListener('click', () => this.el['group-dialog'].showModal());
  }

  ready() { this.el['app-shell'].setAttribute('aria-busy', 'false'); }

  setLanStatus(state, detail) {
    this.el['lan-dot'].className = `status-dot ${state}`;
    this.el['lan-status'].textContent = state === 'ok' ? 'LAN discovery active' : state === 'bad' ? 'LAN discovery interrupted' : 'Connecting…';
    this.el['lan-detail'].textContent = detail;
  }

  setWelcomeProgress(hasPeer, hasSession) {
    this.el['welcome-peer-step'].classList.toggle('done', hasPeer);
    this.el['welcome-session-step'].classList.toggle('done', hasSession);
  }

  showAdvanced(show) {
    this.el['advanced-drawer'].hidden = !show;
    this.el['app-shell'].classList.toggle('drawer-open', show);
  }

  renderConversations(conversations, selectedKey, onSelect) {
    const search = this.el['conversation-search'].value.trim().toLowerCase();
    const visible = conversations.filter(item => !search || `${item.title} ${item.subtitle}`.toLowerCase().includes(search));
    this.el['conversation-list'].replaceChildren(...visible.map(item => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = `conversation-item${item.key === selectedKey ? ' active' : ''}`;
      button.innerHTML = `
        <span class="avatar">${escapeHtml(initials(item.title))}</span>
        <span class="conversation-main"><strong>${escapeHtml(item.title)}</strong><span>${escapeHtml(item.subtitle)}</span></span>
        <span class="conversation-meta"><span>${escapeHtml(item.meta ?? '')}</span>${item.unread ? '<span class="unread-dot"></span>' : ''}</span>`;
      button.addEventListener('click', () => onSelect(item));
      return button;
    }));
    this.el['empty-conversations'].hidden = conversations.length > 0;
  }

  setConversation(conversation) {
    if (conversation?.key !== this.selectedKey) this.closeMessageMenu();
    this.selectedKey = conversation?.key;
    if (!conversation) {
      this.el['welcome-state'].hidden = false;
      this.el['message-view'].hidden = true;
      this.el['message-composer'].hidden = true;
      this.el['chat-title'].textContent = 'HYDRA Chat';
      this.el['chat-subtitle'].textContent = 'Waiting for another local peer…';
      this.el['session-pill'].textContent = 'No session';
      this.el['session-pill'].className = 'pill neutral';
      return;
    }
    this.el['welcome-state'].hidden = true;
    this.el['message-view'].hidden = false;
    this.el['message-composer'].hidden = false;
    this.el['chat-title'].textContent = conversation.title;
    this.el['chat-avatar'].textContent = initials(conversation.title);
    this.el['chat-subtitle'].textContent = conversation.subtitle;
    this.el['session-pill'].textContent = conversation.type === 'lobby' ? `${conversation.memberCount ?? 0} members` : conversation.ready ? 'Encrypted session' : 'Connecting…';
    this.el['session-pill'].className = `pill ${conversation.ready || conversation.type === 'lobby' ? 'ok' : 'warning'}`;
    this.el['send-button'].disabled = conversation.type === 'direct' && !conversation.ready;
    this.el['contact-controls'].hidden = conversation.type !== 'direct';
    this.el['lobby-controls'].hidden = conversation.type !== 'lobby';
  }

  renderMessages(messages, options = {}) {
    this.closeMessageMenu();
    const {
      privacyMode = false,
      preserveIndex,
      preserveScroll = false,
      onToggleMessage = () => {},
      onRemoveLocal = () => {},
      onRequestRemoval = () => {},
      onRemovalDecision = () => {},
    } = options;
    const list = this.el['message-list'];
    const oldScrollTop = list.scrollTop;
    const carrierScrolls = new Map([...list.querySelectorAll('[data-message-key]')].map(row => [
      row.dataset.messageKey,
      row.querySelector('.carrier-body')?.scrollTop ?? 0,
    ]));
    const hadContent = list.childElementCount > 0;
    const oldAnchor = Number.isInteger(preserveIndex)
      ? list.querySelector(`[data-message-index="${preserveIndex}"]`)?.getBoundingClientRect().top
      : undefined;
    const wasNearBottom = list.scrollHeight - list.clientHeight - list.scrollTop < 48;
    const messageByKey = new Map(messages.map((message, index) => [String(message.messageKey ?? `index-${index}`), message]));
    const nodes = messages.map((message, index) => {
      if (message.system) {
        const node = document.createElement('div');
        node.className = 'system-message';
        node.textContent = message.text;
        return node;
      }
      const row = document.createElement('article');
      row.className = `message-row ${message.direction}`;
      row.dataset.messageIndex = String(index);
      row.dataset.messageKey = String(message.messageKey ?? `index-${index}`);
      const attachments = (message.attachments ?? []).map((attachment, attachmentIndex) => {
        const name = privacyMode && !message.privacyRevealed
          ? maskText(attachment.name || `attachment-${attachmentIndex + 1}`)
          : attachment.name || `attachment-${attachmentIndex + 1}`;
        return `<div class="attachment-chip">📎 <span>${escapeHtml(name)}</span><button type="button" data-attachment="${attachmentIndex}">Save</button></div>`;
      }).join('');
      const presentation = messagePresentation(message, privacyMode);
      const { hasCarrier, privacyHidden, showDecoded, body } = presentation;
      const bodyMarkup = privacyHidden
        ? `<p class="message-body privacy-masked-message">${escapeHtml(body)}</p>`
        : hasCarrier && !showDecoded
          ? `<pre class="message-body carrier-body">${escapeHtml(body)}</pre>`
          : `<p class="message-body">${escapeHtml(body)}</p>`;
      const direction = message.direction === 'outgoing' ? 'You' : 'Peer';
      const clickable = privacyMode || hasCarrier;
      const removal = message.removalRequest
        ? `<div class="removal-request"><span>A participant asked to remove this message from your device.</span><div><button type="button" data-removal="accept">Remove</button><button type="button" data-removal="keep">Keep</button></div></div>`
        : '';
      row.innerHTML = `<div class="message-bubble">${bodyMarkup}${attachments ? `<div class="message-attachments">${attachments}</div>` : ''}${removal}<div class="message-time"><span class="direction-label">${direction}</span><span>${escapeHtml(message.time ?? '')}</span>${message.delivery ? `<span>${escapeHtml(message.delivery)}</span>` : ''}</div></div><div class="message-actions-wrap"><button type="button" class="message-menu-button" aria-label="Message actions" aria-haspopup="menu" aria-expanded="false" title="Message actions">⋯</button><div class="message-actions" role="menu" hidden><button type="button" role="menuitem" data-message-action="local">Remove from this device</button><button type="button" role="menuitem" data-message-action="all">Request removal for everyone</button><button type="button" role="menuitem" data-message-action="help">Removal help ?</button></div></div>`;
      row.querySelectorAll('[data-attachment]').forEach(button => button.addEventListener('click', event => {
        event.stopPropagation();
        const attachment = message.attachments[Number(button.dataset.attachment)];
        downloadBytes(attachment.name || 'attachment.bin', attachment.bytes);
      }));
      const menuButton = row.querySelector('.message-menu-button');
      const menu = row.querySelector('.message-actions');
      menuButton.addEventListener('click', event => {
        event.stopPropagation();
        this.toggleMessageMenu(menu, menuButton);
      });
      row.querySelectorAll('[data-message-action]').forEach(button => button.addEventListener('click', event => {
        event.stopPropagation();
        this.closeMessageMenu();
        if (button.dataset.messageAction === 'local') onRemoveLocal(index);
        else if (button.dataset.messageAction === 'all') onRequestRemoval(index);
        else this.showHelp('removal');
      }));
      row.querySelectorAll('[data-removal]').forEach(button => button.addEventListener('click', event => {
        event.stopPropagation();
        onRemovalDecision(index, button.dataset.removal === 'accept');
      }));
      if (clickable) {
        row.querySelector('.message-bubble').addEventListener('click', event => {
          if (event.target.closest('button, a')) return;
          const updated = onToggleMessage(index) ?? message;
          this.updateMessageBody(row, updated, privacyMode, list);
        });
      }
      return row;
    });
    list.replaceChildren(...nodes);
    for (const row of list.querySelectorAll('[data-message-key]')) {
      const carrier = row.querySelector('.carrier-body');
      if (!carrier) continue;
      const saved = carrierScrolls.get(row.dataset.messageKey) ?? messageByKey.get(row.dataset.messageKey)?.carrierScrollTop;
      if (Number.isFinite(saved)) carrier.scrollTop = saved;
    }
    if (Number.isInteger(preserveIndex) && oldAnchor !== undefined) {
      list.scrollTop = oldScrollTop;
      const newAnchor = list.querySelector(`[data-message-index="${preserveIndex}"]`)?.getBoundingClientRect().top;
      if (newAnchor !== undefined) list.scrollTop += newAnchor - oldAnchor;
    } else if (preserveScroll) {
      list.scrollTop = oldScrollTop;
    } else if (wasNearBottom || !hadContent) {
      list.scrollTop = list.scrollHeight;
    } else {
      list.scrollTop = oldScrollTop;
    }
  }

  updateMessageBody(row, message, privacyMode, list) {
    const oldTop = row.getBoundingClientRect().top;
    const oldBody = row.querySelector('.message-body');
    if (!oldBody) return;
    if (oldBody.classList.contains('carrier-body')) message.carrierScrollTop = oldBody.scrollTop;
    const { hasCarrier, privacyHidden, showDecoded, body } = messagePresentation(message, privacyMode);
    const nextBody = document.createElement(hasCarrier && !privacyHidden && !showDecoded ? 'pre' : 'p');
    nextBody.className = `message-body${privacyHidden ? ' privacy-masked-message' : hasCarrier && !showDecoded ? ' carrier-body' : ''}`;
    nextBody.textContent = body;
    oldBody.replaceWith(nextBody);
    if (nextBody.classList.contains('carrier-body') && Number.isFinite(message.carrierScrollTop)) nextBody.scrollTop = message.carrierScrollTop;
    row.querySelectorAll('.attachment-chip span').forEach((span, index) => {
      const name = message.attachments?.[index]?.name || `attachment-${index + 1}`;
      span.textContent = privacyMode && !message.privacyRevealed ? maskText(name) : name;
    });
    const newTop = row.getBoundingClientRect().top;
    list.scrollTop += newTop - oldTop;
  }

  setPrivacyMode(enabled) {
    const active = Boolean(enabled);
    const button = this.el['privacy-toggle'];
    button.setAttribute('aria-pressed', String(active));
    button.classList.toggle('active', active);
    button.title = active ? 'Privacy mask on: typed text and messages are hidden locally' : 'Mask typed text and message contents';
  }

  setCarrierRevealAll(enabled) {
    const active = Boolean(enabled);
    const button = this.el['carrier-view-toggle'];
    button.setAttribute('aria-pressed', String(active));
    button.classList.toggle('active', active);
    button.title = active ? 'Show carrier or masked view for all stego messages' : 'Show decoded text for all stego messages';
  }

  renderPendingAttachments(attachments, remove) {
    this.el['attachment-strip'].hidden = attachments.length === 0;
    this.el['attachment-strip'].replaceChildren(...attachments.map((attachment, index) => {
      const node = document.createElement('span');
      node.className = 'pending-attachment';
      node.innerHTML = `📎 ${escapeHtml(attachment.name)} <button type="button" aria-label="Remove attachment">×</button>`;
      node.querySelector('button').addEventListener('click', () => remove(index));
      return node;
    }));
  }

  setSending(active, label = '') {
    this.el['send-button'].disabled = active || this.el['send-button'].dataset.sessionReady === 'false';
    this.el['send-progress'].hidden = !active;
    this.el['send-progress'].textContent = label;
  }

  setSessionReady(ready) {
    this.el['send-button'].dataset.sessionReady = String(!ready ? false : true);
    this.el['send-button'].disabled = !ready;
  }

  toast(message, kind = '') {
    const node = document.createElement('div');
    node.className = `toast ${kind === 'error' ? 'bad' : kind}`;
    node.textContent = message;
    this.el['toast-region'].append(node);
    window.setTimeout(() => node.remove(), 4200);
  }

  renderIdentityList(identities, activeId) {
    this.el['identity-list'].replaceChildren(...identities.map(identity => compactItem(
      identity.label || `Identity ${identity.id.slice(0, 8)}`,
      `${identity.id.slice(0, 16)}… · ${identity.unlocked ? 'unlocked' : 'locked'}${identity.id === activeId ? ' · active' : ''}`,
    )));
    const select = this.el['identity-select'];
    const previous = select.value;
    select.replaceChildren(...identities.map(identity => new Option(
      `${identity.label || 'Identity'}${identity.id === activeId ? ' · active' : ''}`,
      identity.id,
    )));
    select.value = identities.some(identity => identity.id === previous) ? previous : (activeId || identities[0]?.id || '');
  }

  renderContactLists(contacts) {
    this.el['contact-list-settings'].replaceChildren(...contacts.map(contact => compactItem(
      contact.label || `Peer ${contact.id.slice(0, 8)}`,
      `${contact.id.slice(0, 16)}… · ${contact.verified ? 'verified' : 'unverified'}${contact.blocked ? ' · blocked' : ''}`,
    )));
  }

  renderLobbyMembers(contacts, memberIds, onRemove) {
    const byId = new Map(contacts.map(contact => [contact.id, contact]));
    this.el['lobby-member-list'].replaceChildren(...memberIds.map(id => {
      const contact = byId.get(id);
      const node = compactItem(contact?.label || `Peer ${id.slice(0, 8)}`, `${id.slice(0, 16)}…`);
      if (onRemove && contact) {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'mini-action';
        button.textContent = 'Remove';
        button.addEventListener('click', () => onRemove(id));
        node.append(button);
      }
      return node;
    }));
    this.el['lobby-add-member'].replaceChildren(...contacts.filter(contact => !memberIds.includes(contact.id)).map(contact => new Option(contact.label || `Peer ${contact.id.slice(0, 8)}`, contact.id)));
  }

  renderQuickGroupMembers(peers) {
    this.el['quick-group-members'].replaceChildren(...peers.map(peer => {
      const label = document.createElement('label');
      label.className = 'choice-row';
      label.innerHTML = `<input type="checkbox" value="${escapeHtml(peer.contactId)}" checked><span>${escapeHtml(peer.title)}</span>`;
      return label;
    }));
  }
}

function compactItem(title, subtitle) {
  const node = document.createElement('div');
  node.className = 'compact-item';
  node.innerHTML = `<div><strong>${escapeHtml(title)}</strong><span>${escapeHtml(subtitle)}</span></div>`;
  return node;
}

function initials(value) {
  const parts = value.trim().split(/\s+/).filter(Boolean);
  return (parts.length > 1 ? `${parts[0][0]}${parts.at(-1)[0]}` : (parts[0]?.slice(0, 2) || 'H')).toUpperCase();
}

export function messagePresentation(message, privacyMode = false) {
  const hasCarrier = Boolean(message?.carrier && message?.stegoProfile);
  const privacyHidden = Boolean(privacyMode && !message?.privacyRevealed);
  const showDecoded = privacyMode
    ? Boolean(message?.privacyRevealed)
    : hasCarrier && message?.stegoView === 'decoded';
  const body = privacyHidden
    ? maskText(message?.text)
    : hasCarrier && !showDecoded
      ? message.carrier
      : message?.text ?? '';
  return { hasCarrier, privacyHidden, showDecoded, body };
}

export function maskText(value) {
  return String(value ?? '').replace(/[^\s]/g, '*');
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}
