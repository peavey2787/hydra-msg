import { randomHex } from './bytes.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const GROUP_TEXT_PREFIX = 'HYDRA-GUI-GROUP/1:';

export function newMessageKey() {
  return `m-${randomHex(12)}`;
}

export function newRequestId() {
  return `r-${randomHex(12)}`;
}

export function encodeControl(value) {
  return encoder.encode(JSON.stringify({ v: 1, ...value }));
}

export function decodeControl(bytes) {
  const value = JSON.parse(decoder.decode(bytes));
  if (value?.v !== 1) throw new Error('Unsupported GUI control message version.');
  return value;
}


export function encodeGroupText(lobbyId, text) {
  return `${GROUP_TEXT_PREFIX}${JSON.stringify({ lobbyId, text })}`;
}

export function isGroupText(value) {
  return String(value).startsWith(GROUP_TEXT_PREFIX);
}

export function decodeGroupText(value) {
  if (!isGroupText(value)) throw new Error('Group stego payload is missing its HYDRA GUI group marker.');
  const decoded = JSON.parse(String(value).slice(GROUP_TEXT_PREFIX.length));
  if (typeof decoded?.lobbyId !== 'string' || typeof decoded?.text !== 'string') throw new Error('Group stego payload is malformed.');
  return decoded;
}
