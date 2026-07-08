function renderIdentities(identities, state) {
  const unlocked = new Set(state.unlocked_identity_ids || []);
  const html = identities.map((identity) => `
    <div class="identity-item ${identity.active ? 'active-identity' : ''}">
      <strong>${escapeHtml(identity.label)}${identity.active ? '<span class="badge">active</span>' : ''}${unlocked.has(identity.id) ? '<span class="badge">unlocked</span>' : ''}</strong>
      <div>fingerprint: <code>${escapeHtml(identity.fingerprint)}</code></div>
      <div class="identity-actions">
        <button class="secondary switch-identity" type="button" data-id="${escapeHtml(identity.id)}" ${identity.active ? 'disabled' : ''}>Switch to this identity</button>
      </div>
      <details class="advanced"><summary>Advanced</summary>
        <div>id: <code>${escapeHtml(identity.id)}</code></div>
        <div>device: <code>${escapeHtml(identity.device_id)}</code></div>
        <div>device fingerprint: <code>${escapeHtml(identity.device_fingerprint)}</code></div>
        <div>generation: ${Number(identity.generation)}</div>
        <div>revoked: ${Boolean(identity.revoked)}</div>
      </details>
    </div>
  `).join('');
  $('#identity-list').innerHTML = html || '<p class="muted">No production identities yet.</p>';
  for (const button of $$('.switch-identity')) {
    button.addEventListener('click', async () => {
      await api('/api/identity/switch', {
        method: 'POST',
        body: formBody({ id: button.dataset.id }),
      });
      await refreshState();
    });
  }
}

function renderContacts(contacts) {
  const html = contacts.map((contact) => {
    const state = contact.revoked ? 'revoked' : (contact.trust_state || 'trusted');
    return `
      <div class="contact ${escapeHtml(state)}">
        <strong>${escapeHtml(contact.alias)} <span class="badge">${escapeHtml(state)}</span></strong>
        <div>mailbox: <code>${escapeHtml(contact.mailbox)}</code></div>
        <div>fingerprint: <code>${escapeHtml(contact.fingerprint)}</code></div>
        <div>safety: <code>${escapeHtml(contact.safety)}</code></div>
        <details class="advanced"><summary>Advanced trust details</summary>
          <div>public key: <code>${escapeHtml(contact.public_key_hex || '')}</code></div>
          <div>mailbox binding: <code>${escapeHtml(contact.mailbox_binding || '')}</code></div>
          <div>QR verification payload: <code>${escapeHtml(contact.qr)}</code></div>
          <form class="verify-contact-qr-form form-grid compact-form" data-alias="${escapeHtml(contact.alias)}">
            <label>Compare scanned QR payload<textarea name="qr_payload" placeholder="paste hydra-msg-contact-v1|..."></textarea></label>
            <button type="submit">Verify QR against this contact</button>
          </form>
        </details>
      </div>
    `;
  }).join('');
  $('#contacts-list').innerHTML = html || '<p class="muted">No contacts yet. Review and trust one above.</p>';
  for (const form of $$('.verify-contact-qr-form')) {
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      try {
        const result = await api('/api/contacts/verify-qr', {
          method: 'POST',
          body: formBody({ alias: form.dataset.alias, qr_payload: getFormValue(form, 'qr_payload') }),
        });
        setOutput('#contact-review', result.message);
      } catch (error) {
        setOutput('#contact-review', error.message);
      }
    });
  }
}


function renderChats(chats) {
  if (selectedChatId && !chats.some((chat) => chat.id === selectedChatId)) selectedChatId = null;
  if (!selectedChatId && chats.length) selectedChatId = chats[0].id;
  const directChats = chats.filter((chat) => chat.kind === 'direct');
  const groupChats = chats.filter((chat) => chat.kind !== 'direct');
  const listHtml = directChats.map(chatListItem).join('');
  $('#chat-list').innerHTML = listHtml || '<p class="muted">No direct chats yet. Trust a contact, unlock your identity, then create a direct chat.</p>';
  const groupHtml = groupChats.map(chatListItem).join('');
  $('#group-chat-list').innerHTML = groupHtml || '<p class="muted">No group chat shells yet.</p>';
  for (const button of $$('.select-chat')) {
    button.addEventListener('click', () => {
      selectedChatId = button.dataset.id;
      renderChats((latestState && latestState.chats) || []);
    });
  }
  renderSelectedChat(chats.find((chat) => chat.id === selectedChatId));
}

function chatListItem(chat) {
  const active = chat.id === selectedChatId ? 'active-chat' : '';
  const preview = chat.last_message_preview || 'No messages yet.';
  return `
    <button class="chat-list-item select-chat ${active}" type="button" data-id="${escapeHtml(chat.id)}">
      <strong>${escapeHtml(chat.title)}</strong>
      <span>${escapeHtml(chat.kind)} · ${Number(chat.message_count)} messages</span>
      <small>${escapeHtml(preview)}</small>
    </button>
  `;
}

function renderSelectedChat(chat) {
  const title = $('#active-chat-title');
  const meta = $('#active-chat-meta');
  const thread = $('#message-thread');
  const sendForm = $('#send-message-form');
  const receiveForm = $('#receive-message-form');
  if (!chat) {
    title.textContent = 'No chat selected';
    meta.textContent = 'Select a chat to view messages.';
    thread.innerHTML = 'No messages selected.';
    sendForm.querySelector('button').disabled = true;
    receiveForm.querySelector('button').disabled = true;
    return;
  }
  title.textContent = chat.title;
  meta.textContent = `${chat.kind} · epoch ${chat.current_epoch} · state ${chat.current_state_version}`;
  sendForm.querySelector('button').disabled = false;
  receiveForm.querySelector('button').disabled = false;
  thread.innerHTML = (chat.messages || []).map((message) => `
    <div class="message ${escapeHtml(message.direction)}">
      <strong>${escapeHtml(message.direction)}</strong>
      <p>${escapeHtml(message.content_preview)}</p>
      <small>index ${Number(message.message_index)} · sender ${escapeHtml(message.sender_id.slice(0, 16))}…</small>
    </div>
  `).join('') || '<p class="muted">No messages in this chat yet.</p>';
}

function renderContactReview(result) {
  pendingContactReview = null;
  $('#trust-contact').disabled = true;
  $('#accept-contact-key-change').disabled = true;
  if (result.contact) {
    pendingContactReview = {
      alias: result.contact.alias,
      public_key_hex: result.contact.public_key_hex,
      qr_payload: result.contact.qr,
      key_change: false,
    };
    $('#trust-contact').disabled = Boolean(result.trusted);
    $('#contact-review').innerHTML = `
      <div class="invite-review">
        <strong>${escapeHtml(result.contact.alias)}</strong>
        <div>state: <code>${escapeHtml(result.trust_state)}</code></div>
        <div>safety: <code>${escapeHtml(result.contact.safety)}</code></div>
        <div>fingerprint: <code>${escapeHtml(result.contact.fingerprint)}</code></div>
        <div>mailbox: <code>${escapeHtml(result.contact.mailbox)}</code></div>
        <p class="muted small-text">Compare the safety number out-of-band before trusting this contact.</p>
        <details class="advanced"><summary>Advanced trust details</summary>
          <div>public key: <code>${escapeHtml(result.contact.public_key_hex)}</code></div>
          <div>mailbox binding: <code>${escapeHtml(result.contact.mailbox_binding)}</code></div>
          <div>QR verification payload: <code>${escapeHtml(result.contact.qr)}</code></div>
        </details>
      </div>
    `;
    return;
  }
  if (result.key_change_warning) {
    pendingContactReview = {
      alias: result.alias,
      public_key_hex: getFormValue($('#contact-form'), 'public_key_hex'),
      qr_payload: getFormValue($('#contact-form'), 'qr_payload'),
      key_change: true,
    };
    $('#accept-contact-key-change').disabled = false;
    $('#contact-review').innerHTML = `
      <div class="warning-box">
        <strong>Changed-key warning for ${escapeHtml(result.alias)}</strong>
        <div>old safety: <code>${escapeHtml(result.old_safety)}</code></div>
        <div>new safety: <code>${escapeHtml(result.new_safety)}</code></div>
        <div>old fingerprint: <code>${escapeHtml(result.old_fingerprint)}</code></div>
        <div>new fingerprint: <code>${escapeHtml(result.new_fingerprint)}</code></div>
        <p>${escapeHtml(result.message)}</p>
      </div>
    `;
    return;
  }
  setOutput('#contact-review', result.message || 'No contact review available.');
}


function renderBootstrapInvite(invite, targetSelector) {
  const recipient = invite.recipient_fingerprint_hex || 'open invite';
  const html = `
    <div class="invite-review">
      <strong>${escapeHtml(invite.inviter_label)}</strong>
      <div>safety: <code>${escapeHtml(invite.safety_number)}</code></div>
      <div>fingerprint: <code>${escapeHtml(invite.identity_fingerprint_hex)}</code></div>
      <div>mailbox: <code>${escapeHtml(invite.mailbox_hint)}</code></div>
      <div>recipient: <code>${escapeHtml(recipient)}</code></div>
      <details class="advanced"><summary>Advanced bootstrap details</summary>
        <div>public key: <code>${escapeHtml(invite.public_key_hex)}</code></div>
        <div>device id: <code>${escapeHtml(invite.device_id_hex)}</code></div>
        <div>device fingerprint: <code>${escapeHtml(invite.device_fingerprint_hex)}</code></div>
        <div>context binding: <code>${escapeHtml(invite.context_binding_hex)}</code></div>
        <div>expires: <code>${new Date(Number(invite.expires_at_ms)).toISOString()}</code></div>
      </details>
    </div>
  `;
  $(targetSelector).innerHTML = html;
}

function setQrPayload(joinCode) {
  currentJoinCode = joinCode || '';
  const box = $('#qr-payload-box');
  if (!box) return;
  box.textContent = currentJoinCode || 'Generate an invite to show the payload.';
}


function renderMyContactCard(card) {
  const box = $('#my-contact-card');
  if (!box) return;
  box.innerHTML = `
    <div class="invite-review">
      <strong>${escapeHtml(card.label)}</strong>
      <div>safety: <code>${escapeHtml(card.safety)}</code></div>
      <div>fingerprint: <code>${escapeHtml(card.fingerprint)}</code></div>
      <div>mailbox: <code>${escapeHtml(card.mailbox)}</code></div>
      <label>Join code / QR payload<textarea readonly>${escapeHtml(card.join_code)}</textarea></label>
      <div class="actions">
        <button id="copy-my-contact-join-code" type="button">Copy join code</button>
        <button id="copy-my-contact-public-key" class="secondary" type="button">Copy public key</button>
      </div>
      <p class="muted small-text">Give this join code to your friend. They paste it into Contacts → Contact QR verification payload, choose an alias, review safety, then trust.</p>
      <details class="advanced"><summary>Advanced public contact details</summary>
        <div>public key: <code>${escapeHtml(card.public_key_hex)}</code></div>
        <div>mailbox binding: <code>${escapeHtml(card.mailbox_binding)}</code></div>
      </details>
    </div>
  `;
  $('#copy-my-contact-join-code').addEventListener('click', () => copyText(card.join_code, '#my-contact-card'));
  $('#copy-my-contact-public-key').addEventListener('click', () => copyText(card.public_key_hex, '#my-contact-card'));
}
