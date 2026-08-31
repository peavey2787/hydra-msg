#!/usr/bin/env python3
"""Independent HYDRA handshake transcript/KDF oracle.

This intentionally does not import project code or third-party crypto packages.
X25519 is implemented directly from RFC 7748 using Python integer arithmetic;
SHA3/HMAC use the Python standard library. ML-KEM/ML-DSA primitive outputs are
inputs to this oracle and remain subject to separate cross-implementation review.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "qa/vectors/candidate/handshake"
FROZEN = ROOT / "qa/vectors/independent/handshake-oracle-v1.json"
SUITE_ID = b"HYDRA1-MK768-M65"
BASEPOINT = (9).to_bytes(32, "little")


def read(vector: str, artifact: str) -> bytes:
    return (VECTORS / vector / f"{artifact}.bin").read_bytes()


def lp(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


def x25519(private: bytes, peer_public: bytes) -> bytes:
    if len(private) != 32 or len(peer_public) != 32:
        raise ValueError("X25519 inputs must be 32 bytes")
    scalar_bytes = bytearray(private)
    scalar_bytes[0] &= 248
    scalar_bytes[31] &= 127
    scalar_bytes[31] |= 64
    scalar = int.from_bytes(scalar_bytes, "little")
    modulus = 2**255 - 19
    x1 = int.from_bytes(peer_public, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for bit_index in range(254, -1, -1):
        bit = (scalar >> bit_index) & 1
        swap ^= bit
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = bit
        a = (x2 + z2) % modulus
        aa = a * a % modulus
        b = (x2 - z2) % modulus
        bb = b * b % modulus
        e = (aa - bb) % modulus
        c = (x3 + z3) % modulus
        d = (x3 - z3) % modulus
        da = d * a % modulus
        cb = c * b % modulus
        x3 = (da + cb) ** 2 % modulus
        z3 = x1 * (da - cb) ** 2 % modulus
        x2 = aa * bb % modulus
        z2 = e * (aa + 121665 * e) % modulus
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, modulus - 2, modulus) % modulus).to_bytes(32, "little")


def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    output = bytearray()
    block = b""
    counter = 1
    while len(output) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha3_256).digest()
        output.extend(block)
        counter += 1
    return bytes(output[:length])


def expand32(key: bytes, label: bytes, context: bytes) -> bytes:
    return hkdf_expand(key, lp(label) + lp(context))


def computed_values() -> dict[str, str]:
    init_private = read("TV-HS-INIT-000", "x25519_private")
    resp_private = read("TV-HS-RESP-000", "x25519_private")
    init_public = x25519(init_private, BASEPOINT)
    resp_public = x25519(resp_private, BASEPOINT)
    shared_i = x25519(init_private, resp_public)
    shared_r = x25519(resp_private, init_public)
    if shared_i != shared_r:
        raise AssertionError("independent X25519 role agreement failed")

    init_core = read("TV-HS-INIT-000", "core")
    init_signature = read("TV-HS-INIT-000", "signature")
    resp_core = read("TV-HS-RESP-000", "core")
    resp_signature = read("TV-HS-RESP-000", "signature")
    init_signature_digest = hashlib.sha3_512(
        b"HYDRA-MSG/v1/init-signature" + SUITE_ID + lp(init_core)
    ).digest()
    init_hash = hashlib.sha3_512(
        b"HYDRA-MSG/v1/transcript" + lp(init_core + init_signature)
    ).digest()
    resp_signature_digest = hashlib.sha3_512(
        b"HYDRA-MSG/v1/resp-signature" + SUITE_ID + init_hash + lp(resp_core)
    ).digest()
    transcript_hash = hashlib.sha3_512(
        b"HYDRA-MSG/v1/transcript"
        + lp(init_core + init_signature)
        + lp(resp_core + resp_signature)
    ).digest()

    mlkem_shared = read("TV-HS-KDF-000", "mlkem_shared_secret")
    mlkem_decapsulated = read("TV-HS-KDF-000", "mlkem_decapsulated_secret")
    if mlkem_shared != mlkem_decapsulated:
        raise AssertionError("committed ML-KEM role outputs disagree")
    hybrid_ikm = lp(shared_i) + lp(mlkem_shared)
    hybrid_prk = hmac.new(transcript_hash, hybrid_ikm, hashlib.sha3_256).digest()
    handshake_secret = expand32(hybrid_prk, b"HYDRA-MSG/v1/root-key", transcript_hash)
    session_id = expand32(handshake_secret, b"HYDRA-MSG/v1/session-id", transcript_hash)
    confirm_key = expand32(handshake_secret, b"HYDRA-MSG/v1/confirm-key", transcript_hash)
    finish_key = expand32(handshake_secret, b"HYDRA-MSG/v1/finish-key", transcript_hash)
    confirm_input = b"HYDRA-MSG/v1/resp-confirm" + transcript_hash + session_id
    resp_confirm = hmac.new(confirm_key, confirm_input, hashlib.sha3_256).digest()

    values = {
        "initiator_x25519_public": init_public,
        "responder_x25519_public": resp_public,
        "x25519_shared_secret": shared_i,
        "init_signature_digest": init_signature_digest,
        "init_hash": init_hash,
        "resp_signature_digest": resp_signature_digest,
        "transcript_hash": transcript_hash,
        "hybrid_ikm": hybrid_ikm,
        "hybrid_prk": hybrid_prk,
        "handshake_secret": handshake_secret,
        "session_id": session_id,
        "confirm_key": confirm_key,
        "finish_key": finish_key,
        "resp_confirm": resp_confirm,
    }
    return {name: value.hex() for name, value in values.items()}


def candidate_value(name: str) -> bytes:
    locations = {
        "initiator_x25519_public": ("TV-HS-KDF-000", "initiator_x25519_public"),
        "responder_x25519_public": ("TV-HS-KDF-000", "responder_x25519_public"),
        "x25519_shared_secret": ("TV-HS-KDF-000", "x25519_shared_secret"),
        "init_signature_digest": ("TV-HS-INIT-000", "signature_digest"),
        "init_hash": ("TV-HS-INIT-000", "init_hash"),
        "resp_signature_digest": ("TV-HS-RESP-000", "signature_digest"),
        "transcript_hash": ("TV-HS-RESP-000", "transcript_hash"),
        "hybrid_ikm": ("TV-HS-KDF-000", "hybrid_ikm"),
        "hybrid_prk": ("TV-HS-KDF-000", "hybrid_prk"),
        "handshake_secret": ("TV-HS-KDF-000", "handshake_secret"),
        "session_id": ("TV-HS-KDF-000", "session_id"),
        "confirm_key": ("TV-HS-KDF-000", "confirm_key"),
        "finish_key": ("TV-HS-KDF-000", "finish_key"),
        "resp_confirm": ("TV-HS-RESP-000", "resp_confirm"),
    }
    vector, artifact = locations[name]
    return read(vector, artifact)


def main() -> int:
    frozen = json.loads(FROZEN.read_text(encoding="utf-8"))
    expected = frozen["expected"]
    computed = computed_values()
    failures: list[str] = []
    for name, expected_hex in expected.items():
        actual_hex = computed.get(name)
        if actual_hex != expected_hex:
            failures.append(f"independent oracle mismatch for {name}")
            continue
        if candidate_value(name).hex() != expected_hex:
            failures.append(f"candidate artifact mismatch for {name}")
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print(
        "Independent handshake oracle passed: RFC7748 X25519 plus independent "
        "SHA3/HMAC/HKDF transcript and key schedule match the frozen v1 values."
    )
    print("ML-KEM/ML-DSA primitive cross-implementation corroboration remains separate evidence.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
