const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));
let currentJoinCode = '';
let pendingContactReview = null;
let selectedChatId = null;
let latestState = null;

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set('X-Hydra-Gui-Token', window.HYDRA_GUI_TOKEN || '');
  headers.set('X-Requested-With', 'HYDRA-MSG-GUI');
  const response = await fetch(path, { ...options, headers });
  const data = await response.json();
  if (!data.ok) throw new Error(data.error || 'request failed');
  return data;
}

function formBody(fields) {
  const body = new URLSearchParams();
  for (const [key, value] of Object.entries(fields)) body.set(key, value == null ? '' : value);
  return body;
}

function setStatus(message) {
  const status = $('#app-status');
  if (status) status.textContent = message || '';
}

function setOutput(selector, message) {
  const output = $(selector);
  if (output) output.textContent = message;
  setStatus(message);
}

