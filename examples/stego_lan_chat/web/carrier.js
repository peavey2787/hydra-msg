export async function encodeCarrier(packet, profile) {
  const format = profileFormat(profile);
  const response = await fetch(format.hidePath, {
    method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream' },
    body: packet,
  });
  if (!response.ok) throw new Error(await response.text());
  return {
    representation: format.representation,
    text: await response.text(),
    encryptedBytes: packet.byteLength,
  };
}

export async function decodeCarrier(carrier) {
  if (typeof carrier.text !== 'string') {
    throw new Error('Unsupported or malformed carrier representation.');
  }
  const path = {
    'fast-cover': '/api/stego/reveal-fast',
    'fast-hybrid-cover': '/api/stego/reveal-fast-hybrid',
    'deterministic-cover': '/api/stego/reveal-deterministic',
    'arithmetic-cover': '/api/stego/reveal',
    cover: '/api/stego/reveal',
  }[carrier.representation];
  if (!path) throw new Error('Unsupported or malformed carrier representation.');
  const response = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    body: carrier.text,
  });
  if (!response.ok) throw new Error(await response.text());
  return new Uint8Array(await response.arrayBuffer());
}

export function describeCarrier(carrier) {
  if (carrier.representation === 'fast-cover') {
    return `[fast Unicode carrier: ${carrier.encryptedBytes ?? 'unknown'} encrypted bytes in the trailing invisible-selector layer]\n${carrier.text}`;
  }
  if (carrier.representation === 'fast-hybrid-cover') {
    return `[fast hybrid prose carrier: ${carrier.encryptedBytes ?? 'unknown'} encrypted bytes represented by grammatical word and sentence choices]\n${carrier.text}`;
  }
  if (carrier.representation === 'deterministic-cover') {
    return `[instant zero-model carrier: ${carrier.encryptedBytes ?? 'unknown'} encrypted bytes represented by CFG, lexical, and writing-register choices]\n${carrier.text}`;
  }
  if (carrier.representation === 'arithmetic-cover' || carrier.representation === 'cover') {
    return carrier.text;
  }
  return '[unsupported carrier]';
}

function profileFormat(profile) {
  const format = {
    fast: {
      hidePath: '/api/stego/hide-fast',
      representation: 'fast-cover',
    },
    'fast-hybrid': {
      hidePath: '/api/stego/hide-fast-hybrid',
      representation: 'fast-hybrid-cover',
    },
    deterministic: {
      hidePath: '/api/stego/hide-deterministic',
      representation: 'deterministic-cover',
    },
    arithmetic: {
      hidePath: '/api/stego/hide',
      representation: 'arithmetic-cover',
    },
  }[profile];
  if (!format) throw new Error(`Unsupported stego profile: ${profile}`);
  return format;
}
