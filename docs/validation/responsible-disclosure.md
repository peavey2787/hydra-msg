# HYDRA-MSG responsible disclosure

## Navigation

- [Main README](../../README.md)
- [Spec document index](../spec/README.md)
- [Protocol spec](../spec/protocol-spec.md)
- [Threat model](../spec/threat-model.md)
- [Security proof sketch](../spec/security-proof-sketch.md)
- [State machines](../spec/state-machines.md)
- [Envelope serialization](../spec/envelope-serialization.md)
- [Chain-key evolution](../spec/chain-key-evolution.md)
- [TreeKEM profile](../spec/tree-kem.md)
- [Group modes](../spec/group-modes.md)
- [Group rekey](../spec/group-rekey.md)
- [Anonymous authorization](../spec/anonymous-authorization.md)

HYDRA-MSG uses the repository-root [`SECURITY.md`](../../SECURITY.md) file as the public security policy and GitHub Private Vulnerability Reporting as the private reporting path.

## Current channel

```text
Repository: https://github.com/peavey2787/hydra-msg
Security policy file: SECURITY.md at repository root
Private report URL: https://github.com/peavey2787/hydra-msg/security/advisories/new
```

## Required release evidence

Record the following in the release evidence:

```text
SECURITY.md exists at repository root
reporting URL
supported versions text
initial acknowledgement target
triage target
advisory publication path
```

## Public disclosure rule

Do not publish vulnerability details before coordinated disclosure through the advisory process. Public issues should not contain exploit details, vulnerable code paths, proof-of-concept inputs, private keys, or crash artifacts.

## Report handling

Reports should include enough detail to reproduce the issue: affected commit/version, environment, impact, steps to reproduce, logs or minimized inputs when safe, and suggested regression tests if available.
