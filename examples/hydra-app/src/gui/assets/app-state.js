async function refreshState() {
  const state = await api('/api/state');
  applyShellMode(state);
  $('#identity-status').textContent = state.identity_count ? (state.active_identity_label || 'Ready') : 'Not created';
  $('#conversation-count').textContent = state.conversation_count;
  $('#message-count').textContent = state.message_count;
  $('#contact-count').textContent = state.contacts.length;
  $('#state-output').textContent = JSON.stringify(state, null, 2);
  updateConfigSummary(state);
  for (const input of $$('[data-key]')) {
    const key = input.dataset.key;
    const value = state[key];
    if (input.type === 'checkbox') input.checked = Boolean(value);
    else if (Array.isArray(value)) input.value = value.join('\n');
    else input.value = value ?? '';
  }
  latestState = state;
  renderSessionStatus(state);
  renderIdentities(state.identities || [], state);
  renderContacts(state.contacts || []);
  renderChats(state.chats || []);
  renderRecoveryStatus(state.recovery_status || null);
  setStatus('App state refreshed.');
}


function updateConfigSummary(state) {
  const dataDir = $('#config-data-dir-label');
  const secret = $('#config-storage-secret-label');
  const incomingPolicy = $('#config-incoming-policy-label');
  if (dataDir) dataDir.textContent = state.data_dir || 'default';
  const dataDirDetail = $('#config-data-dir-detail');
  if (dataDirDetail) dataDirDetail.textContent = state.data_dir || 'default';
  if (secret) secret.textContent = state.storage_secret_source || 'unknown';
  if (incomingPolicy) incomingPolicy.textContent = state.incoming_message_policy || 'contacts-only';
}

function applyShellMode(state) {
  const setup = $('#setup-screen');
  const shell = $('#app-shell');
  if (state.first_run_required) {
    setup.classList.remove('hidden');
    shell.classList.add('hidden');
  } else {
    setup.classList.add('hidden');
    shell.classList.remove('hidden');
  }
}

function renderSessionStatus(state) {
  const badge = $('#identity-lock-badge');
  if (!badge) return;
  const unlocked = Boolean(state.identity_session_unlocked);
  const rememberText = state.remember_expires_at_ms
    ? ` · remembered until ${new Date(Number(state.remember_expires_at_ms)).toLocaleString()}`
    : '';
  badge.textContent = unlocked
    ? `unlocked (${Number(state.unlocked_identity_count || 0)})${rememberText}`
    : 'locked';
  badge.classList.toggle('unlocked', unlocked);
  const timeoutInput = $('#idle-timeout-form input[name="seconds"]');
  if (timeoutInput) timeoutInput.value = state.idle_timeout_seconds || '';
}


function renderRecoveryStatus(status) {
  const badge = $('#rollback-badge');
  const panel = $('#recovery-status');
  if (!badge || !panel) return;
  if (!status) {
    badge.textContent = 'unknown';
    panel.textContent = 'Storage recovery status unavailable.';
    return;
  }
  const rollback = Boolean(status.possible_rollback);
  badge.textContent = rollback ? 'rollback warning' : 'ok';
  badge.classList.toggle('warning', rollback);
  panel.classList.toggle('warning-box', rollback);
  const warning = status.rollback_warning ? `<p class="danger-text">${escapeHtml(status.rollback_warning)}</p>` : '';
  panel.innerHTML = `
    ${warning}
    <div>encrypted message DB: <strong>${status.message_store_present ? 'present' : 'not created yet'}</strong></div>
    <div>conversations: <strong>${status.message_store_conversation_count ?? 'locked/unknown'}</strong></div>
    <div>messages: <strong>${status.message_store_message_count ?? 'locked/unknown'}</strong></div>
    <div>live-state DB: <strong>${status.live_state_present ? 'present' : 'not created yet'}</strong></div>
    <div>local live-state sequence: <strong>${status.live_state_sequence ?? 'none'}</strong></div>
    <div>signed checkpoints: <strong>${Number(status.signed_history_checkpoint_count || 0)}</strong></div>
    <div>newest checkpoint sequence: <strong>${status.newest_signed_checkpoint_sequence ?? 'none'}</strong></div>
    <p class="muted small-text">${escapeHtml(status.status_message || '')}</p>
  `;
}

