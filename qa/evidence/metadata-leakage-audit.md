# HYDRA Metadata-Leakage Audit

HYDRA minimizes avoidable SDK-level metadata leakage, but it is not metadata-free and it is not anonymous by default. The implementation encrypts message contents and protected protocol metadata, uses fixed-size encrypted transport packets by default, dynamically chunks valid large messages, pads backup/state storage chunks, exposes randomized lobby routing hints for privacy-oriented carriers, and redacts production storage diagnostics.

## Protected by HYDRA

- Message plaintext and attachments inside HYDRA encrypted envelopes.
- Protected inner protocol metadata inside the authenticated protected record.
- Fragment records and fragment payload lengths inside encrypted fixed-size packets.
- Local state snapshot plaintext inside encrypted chunked storage records.
- Backup snapshot plaintext inside encrypted chunked backup records.
- Debug storage counts and generations are separated from the redacted production storage status API.

## Minimized by HYDRA

- Packet payload length: outbound sends use fixed HYDRA envelope sizes and automatic fragmentation.
- Storage size: encrypted state and backup data are split into fixed-size encrypted storage chunks; the final chunk is authenticated padding.
- routing metadata: Lobby delivery routing: carriers that support mailbox-style routing should use randomized `routing_hint()` values instead of stable contact identifiers.
- Browser persistence metadata: IndexedDB records use revision compare-and-swap and omit durable write timestamps such as `updatedAtMs`.

## Still visible by design

- packet count, direction, timing, retry behavior, and delivery failure shape.
- Lobby fanout count unless the carrier adds relay/mix/broadcast cover behavior.
- Local file existence, IndexedDB record existence, browser origin, quota behavior, and operating-system/storage-provider metadata.
- Backup/state chunk count, KDF algorithm/profile/parameters, salt, nonce/header fields, and file access timing.
- Anonymous-auth token issuance/redemption timing and nullifier reuse behavior.

## Anonymous-auth linkability boundary

anonymous-auth metadata is minimized but not eliminated.

HYDRA anonymous auth is bearer-token based. It is replay-resistant through nullifiers, but it is not fully unlinkable. A token or nullifier can link activity if reused, logged, or correlated by issuer/carrier timing. Production use requires fresh tokens, short expirations, fresh scopes where possible, no token reuse, no nullifier logging, and separate issuance/redemption transport where possible.

Stronger anonymity claims require future blind credentials, ZK nullifier proofs, unlinkable issuance/redemption, and scope-specific unlinkable nullifiers. Bearer tokens must not be marketed as blind credentials or ZK anonymous credentials.

## Browser persistence metadata boundary

browser persistence metadata remains local-environment metadata.

Browser persistence is local-environment metadata. HYDRA fails closed when IndexedDB is unavailable, performs profile revision compare-and-swap to prevent last-writer-wins data loss, and stores no durable `updatedAtMs` write timestamp. Browsers, mobile operating systems, and storage providers can still observe origin storage existence, quota/eviction behavior, record size, and access timing.

## Backup metadata boundary

Backup metadata remains visible at the container/header level even though backup plaintext is encrypted and chunk padded.

Backups are encrypted and padded into fixed-size chunks, but the backup container still exposes the HYDRA backup marker, KDF parameters, salt, nonce/header metadata, chunk count, and file existence/access timing. Chunking hides exact snapshot size, not the coarse total chunk count.

## Transport boundary

HYDRA does not solve traffic-flow confidentiality by itself. Hiding timing, endpoint metadata, relay logs, and traffic shape requires carrier-level batching, mailbox indirection, cover traffic, relay/mix behavior, or another anonymity network.
