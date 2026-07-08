function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
}

function getFormValue(form, name) {
  return new FormData(form).get(name) || '';
}

function getCheckboxValue(form, name) {
  return new FormData(form).get(name) === 'on' ? 'true' : 'false';
}

function addRememberPayload(form, payload) {
  if (!form.querySelector('[name="remember_me"]')) return;
  payload.remember_me = getCheckboxValue(form, 'remember_me');
  payload.remember_duration = getFormValue(form, 'remember_duration') || 'session';
  payload.remember_custom_seconds = getFormValue(form, 'remember_custom_seconds');
}

async function handleIdentityForm(form, path, fields, successLabel) {
  const payload = {};
  for (const field of fields) payload[field] = getFormValue(form, field);
  if (fields.includes('preserve_device_id')) payload.preserve_device_id = getCheckboxValue(form, 'preserve_device_id');
  addRememberPayload(form, payload);
  setOutput('#setup-output', `${successLabel}...`);
  const result = await api(path, { method: 'POST', body: formBody(payload) });
  setOutput('#setup-output', `${result.message}: ${result.identity.label}\nfingerprint: ${result.identity.fingerprint}`);
  form.reset();
  await refreshState();
}

function activateTab(button, options = {}) {
  const panel = document.getElementById(button.dataset.tab);
  if (!panel) return;
  $$('.nav').forEach((item) => {
    const selected = item === button;
    item.classList.toggle('active', selected);
    item.setAttribute('aria-selected', String(selected));
    item.tabIndex = selected ? 0 : -1;
  });
  $$('.tab').forEach((item) => item.classList.toggle('active', item === panel));
  setStatus(`${button.textContent.trim()} opened.`);
  if (options.focusPanel) panel.focus({ preventScroll: false });
}

function focusAdjacentTab(current, direction) {
  const tabs = $$('.nav');
  const index = tabs.indexOf(current);
  if (index < 0) return;
  const next = tabs[(index + direction + tabs.length) % tabs.length];
  activateTab(next);
  next.focus();
}

for (const button of $$('.nav')) {
  button.addEventListener('click', () => activateTab(button, { focusPanel: true }));
  button.addEventListener('keydown', (event) => {
    if (event.key === 'ArrowRight' || event.key === 'ArrowDown') {
      event.preventDefault();
      focusAdjacentTab(button, 1);
    } else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') {
      event.preventDefault();
      focusAdjacentTab(button, -1);
    } else if (event.key === 'Home') {
      event.preventDefault();
      const first = $$('.nav')[0];
      activateTab(first);
      first.focus();
    } else if (event.key === 'End') {
      event.preventDefault();
      const tabs = $$('.nav');
      const last = tabs[tabs.length - 1];
      activateTab(last);
      last.focus();
    }
  });
}

async function copyText(value, fallbackSelector) {
  try {
    await navigator.clipboard.writeText(value || '');
    setStatus('Copied to clipboard.');
  } catch (_error) {
    setOutput(fallbackSelector, value || 'Nothing to copy.');
  }
}
