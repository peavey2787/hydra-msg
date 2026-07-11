# HYDRA-MSG security advisory policy

## Navigation

- [Main README](../../../README.md)
- [Validation index](../README.md)
- [Spec document index](../../spec/README.md)
- [Threat model](../../spec/threat-model.md)

## Reporting channel

The repository security policy is [`SECURITY.md`](../../../SECURITY.md). Vulnerabilities should be reported through GitHub Private Vulnerability Reporting for:

```text
https://github.com/peavey2787/hydra-msg
```

## Severity handling

Use conservative severity. Treat the following as high or critical until disproven:

```text
key compromise
plaintext exposure
authentication bypass
signature/transcript validation bypass
replay acceptance or counter rollback
state rollback bypass
wrong-password state or backup acceptance
browser persistence plaintext fallback or stale-write acceptance
resource-exhaustion bypass before limits
scope/action bypass in anonymous authorization
release artifact/signature/SBOM compromise
```

## Advisory contents

A published advisory should include:

```text
affected versions
fixed versions
impact
workarounds
credit, if requested
technical summary
upgrade instructions
artifact hashes for the fixed release
signature verification instructions
regression tests or evidence references when safe to disclose
```

## Embargo and disclosure

Private reports should remain private until a fix and release are ready, unless active exploitation or user safety requires earlier disclosure.

## Advisory publication location

The preferred publication path is GitHub Security Advisories for `https://github.com/peavey2787/hydra-msg`. If another advisory channel is used, release notes must link it.
