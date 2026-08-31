export function bytesToBase64(bytes) {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = '';
  const step = 0x8000;
  for (let offset = 0; offset < view.length; offset += step) {
    binary += String.fromCharCode(...view.subarray(offset, offset + step));
  }
  return btoa(binary);
}

export function base64ToBytes(value) {
  const binary = atob(value.trim());
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

export function bytesToHex(bytes) {
  return [...new Uint8Array(bytes)].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(value) {
  const hex = value.trim();
  if (!hex || hex.length % 2 || !/^[0-9a-f]+$/i.test(hex)) throw new Error('Expected even-length hexadecimal data.');
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  return bytes;
}

export function randomHex(bytes = 16) {
  const value = new Uint8Array(bytes);
  crypto.getRandomValues(value);
  return bytesToHex(value);
}

export function randomPassword() {
  return `${randomHex(24)}-${randomHex(8)}`;
}

export function downloadBytes(filename, bytes, type = 'application/octet-stream') {
  const blob = new Blob([bytes], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export async function readFile(input) {
  const file = input.files?.[0];
  if (!file) throw new Error('Choose a file first.');
  return new Uint8Array(await file.arrayBuffer());
}

export function jsArray(value) {
  return Array.from(value ?? []);
}
