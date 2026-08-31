#!/usr/bin/env python3
"""Fail closed if hydra-stego's intentionally small public facade expands."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
LIB = ROOT / "crates/hydra-stego/src/lib.rs"
API = ROOT / "crates/hydra-stego/src/api.rs"


def fail(message: str) -> None:
    raise SystemExit(f"stego API shape check failed: {message}")


def main() -> None:
    lib = LIB.read_text(encoding="utf-8")
    api = API.read_text(encoding="utf-8")

    required_public_lines = {
        "pub use api::{Stego, StegoProfile};",
        "pub use error::StegoError;",
        "pub mod model {",
        "pub use crate::generative::{LanguageModel, ModelConfig, TokenCandidate, TokenId};",
        "pub use crate::process::{ProcessLanguageModel, ProcessModelConfig};",
    }
    observed_public_lines = {
        line.strip()
        for line in lib.splitlines()
        if line.strip().startswith(("pub use ", "pub mod "))
    }
    if observed_public_lines != required_public_lines:
        fail(
            "crate-root public exports changed; expected "
            f"{sorted(required_public_lines)}, observed {sorted(observed_public_lines)}"
        )
    if re.search(r"^pub\s+(?:struct|enum|trait|type|fn|const)\b", lib, re.MULTILINE):
        fail("crate root must not declare additional public items")

    forbidden_root_names = {
        "Carrier",
        "HydraStego",
        "StegoMode",
        "DeterministicCodec",
        "GenerativeCodec",
        "GenerativeConfig",
    }
    for name in forbidden_root_names:
        if re.search(rf"\bpub\s+use\b[^;]*\b{re.escape(name)}\b", lib):
            fail(f"implementation type leaked from crate root: {name}")

    public_methods = set(
        re.findall(r"\bpub\s+(?:const\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)", api)
    )
    expected_methods = {
        "requires_model",
        "new",
        "with_model",
        "encode",
        "encode_with_progress",
        "decode",
    }
    if public_methods != expected_methods:
        fail(
            "public facade methods changed; expected "
            f"{sorted(expected_methods)}, observed {sorted(public_methods)}"
        )

    if "pub enum StegoProfile" not in api or "pub struct Stego" not in api:
        fail("Stego and StegoProfile must remain the only facade types")

    for path in [
        ROOT / "crates/hydra-stego/src/deterministic/codec.rs",
        ROOT / "crates/hydra-stego/src/generative/mod.rs",
    ]:
        text = path.read_text(encoding="utf-8")
        if re.search(r"\bpub\s+struct\s+(?:DeterministicCodec|GenerativeCodec)\b", text):
            fail(f"internal codec became public: {path.relative_to(ROOT)}")

    print("stego public API shape checks passed.")


if __name__ == "__main__":
    main()
