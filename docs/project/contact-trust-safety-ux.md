# Contact Trust and Safety Verification UX

Status: P5 implementation note.

This document records the production GUI contact-trust behavior added in P5.

## Source ownership

- `hydra-app-core::ContactTrustStore` owns encrypted contact trust records, safety numbers, mailbox binding derivation, QR payload validation, and key-change warnings.
- `hydra-app::contacts::ContactBook` is the CLI/GUI adapter over the app-core trust store.
- `hydra-app::gui` owns only the local browser UX and API routing for review, trust, and QR comparison.

GUI code must not define contact fingerprints, mailbox bindings, safety numbers, or key-change rules independently.

## Contact states

The GUI represents contact trust as:

- `trusted`: a saved contact whose pinned public key, fingerprint, mailbox binding, and safety number validate;
- `unverified`: a reviewed public key or QR payload that has not yet been explicitly trusted;
- `changed-key-warning`: a submitted key or QR payload conflicts with an existing trusted alias;
- `revoked`: reserved UI state for future revocation plumbing. P5 does not add contact revocation storage.

## Safety decision flow

Adding a contact is now a two-step flow:

1. Review the submitted public key or QR verification payload.
2. Explicitly trust the reviewed contact after comparing the displayed safety number.

New contacts are not silently saved by the review step.

Changed keys are never accepted silently. A changed key requires a separate `Accept verified key change` decision after the new safety number or QR payload has been checked.

## QR verification

Contact QR payloads use the existing app-core contact QR format and are checked against:

- public key;
- identity fingerprint;
- mailbox hint;
- safety number.

The GUI can compare a pasted/scanned QR payload against an already trusted contact. A mismatch is reported without changing stored trust.

## Mailbox binding

Mailbox binding is shown under `Advanced` because normal users should not need it for basic safety verification. It remains visible for expert review and debugging.

## Security boundaries

- Trust-changing operations are POST requests and remain protected by the GUI token and Origin/Referer checks.
- Contact review does not save state.
- Contact trust save requires explicit safety confirmation.
- Key-change save requires explicit key-change acceptance.
- Contact private keys are never involved in the contact trust flow.
- Public keys, fingerprints, safety numbers, mailbox hints, mailbox bindings, and QR payloads are public verification metadata.

## Intentionally not implemented in P5

- Contact revocation persistence.
- Remote directory lookup.
- Production relay/mailbox service.
- Automatic trust on join-code review.
- Background contact sync.
