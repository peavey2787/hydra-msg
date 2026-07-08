# HYDRA carrier examples

## Navigation

- [Main README](../../README.md)
- [How HYDRA messaging works](message-flow/README.md)
- [Examples](../../examples/README.md)

HYDRA carriers move opaque bytes. They are not protocol authority.

The public `hydra-msg` facade owns:

```text
identity
contact trust
handshakes
session creation
encryption/decryption
message payload parsing
lobby envelope creation/parsing
```

Carriers own only byte movement:

```text
WebRTC
libp2p
HTTP
files
QR codes
manual copy/paste
relays
Kaspa pointers
mailboxes
```

A carrier must not inspect, reinterpret, mutate, or authorize HYDRA protocol
state. It can route bytes, retry bytes, persist bytes, or display bytes, but the
only code that decides whether those bytes are valid HYDRA data is the
`hydra-msg` facade.

## Manual file carrier

`examples/manual_file_carrier` writes HYDRA contact cards, handshake offers,
handshake answers, and encrypted envelopes to files. The files are just a manual
carrier. The example exists to make the transport-agnostic rule obvious:

```text
HYDRA creates opaque bytes → file carrier moves bytes → HYDRA consumes bytes
```

## WebRTC manual carrier

`examples/webrtc_manual_carrier` demonstrates a browser WebRTC DataChannel as a
carrier over the `hydra-msg-wasm` facade.

The contact-card exchange is deliberately manual and out-of-band:

```text
1. Alice creates a HYDRA contact card.
2. Bob creates a HYDRA contact card.
3. Alice and Bob copy/paste or otherwise exchange contact cards manually.
4. Each user imports and verifies the other user's contact card.
5. Only then does the WebRTC DataChannel carry HYDRA handshake bytes.
6. After the HYDRA handshake, the DataChannel carries encrypted HYDRA envelopes.
```

The WebRTC example also uses manual SDP copy/paste for signaling so the example
has no signaling-server dependency. This SDP copy/paste is WebRTC setup only; it
is not HYDRA contact-card exchange and it is not protocol authority.

## Future carriers

Future examples can add HTTP, libp2p, relays, Kaspa pointers, or mailbox nodes as
long as they follow the same rule:

```text
carrier in, carrier out, HYDRA remains the only protocol authority
```
