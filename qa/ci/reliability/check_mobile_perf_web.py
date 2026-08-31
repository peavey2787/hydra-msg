#!/usr/bin/env python3
"""Shared mobile/browser persistence benchmark static checks."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
APP_JS = REPO_ROOT / "examples/mobile_perf_web/web/app.js"
SERVER_RS = REPO_ROOT / "examples/mobile_perf_web/src/main.rs"


@dataclass(frozen=True)
class CallSite:
    name: str
    start: int
    end: int
    text: str
    args: tuple[str, ...]
    line: int


def fail(message: str) -> "NoReturn":
    raise SystemExit(message)


def require_text(text: str, needle: str, description: str, path: Path) -> None:
    if needle not in text:
        fail(f"mobile perf web check missing: {description}; expected {needle!r} in {path.relative_to(REPO_ROOT)}")


def forbid_text(text: str, needle: str, description: str, path: Path) -> None:
    if needle in text:
        fail(f"mobile perf web check found forbidden text: {description}; forbidden {needle!r} in {path.relative_to(REPO_ROOT)}")


def split_top_level_args(source: str) -> tuple[str, ...]:
    args: list[str] = []
    start = 0
    paren = bracket = brace = 0
    quote: str | None = None
    escaped = False

    for index, char in enumerate(source):
        if quote is not None:
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if char == quote:
                quote = None
            continue

        if char in "'\"`":
            quote = char
        elif char == "(":
            paren += 1
        elif char == ")":
            paren -= 1
        elif char == "[":
            bracket += 1
        elif char == "]":
            bracket -= 1
        elif char == "{":
            brace += 1
        elif char == "}":
            brace -= 1
        elif char == "," and paren == bracket == brace == 0:
            args.append(source[start:index].strip())
            start = index + 1

    tail = source[start:].strip()
    if tail or args:
        args.append(tail)
    return tuple(args)


def find_calls(source: str, name: str) -> list[CallSite]:
    calls: list[CallSite] = []
    pattern = re.compile(rf"\b{re.escape(name)}\s*\(")

    for match in pattern.finditer(source):
        open_paren = source.find("(", match.start())
        depth = 1
        index = open_paren + 1
        quote: str | None = None
        escaped = False

        while index < len(source) and depth:
            char = source[index]
            if quote is not None:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
            else:
                if char in "'\"`":
                    quote = char
                elif char == "(":
                    depth += 1
                elif char == ")":
                    depth -= 1
            index += 1

        if depth:
            fail(f"mobile perf web check could not parse {name} call beginning on line {source.count(chr(10), 0, match.start()) + 1}")

        args_text = source[open_paren + 1 : index - 1]
        calls.append(
            CallSite(
                name=name,
                start=match.start(),
                end=index,
                text=source[match.start():index],
                args=split_top_level_args(args_text),
                line=source.count("\n", 0, match.start()) + 1,
            )
        )
    return calls


def line_text(source: str, line: int) -> str:
    lines = source.splitlines()
    return lines[line - 1] if 1 <= line <= len(lines) else ""


def check_passworded_open_calls(source: str) -> None:
    persistent_calls = find_calls(source, "openPersistent")
    ephemeral_calls = find_calls(source, "openEphemeral")

    bad_persistent = [call for call in persistent_calls if len(call.args) < 2]
    if bad_persistent:
        for call in bad_persistent:
            print(f"{APP_JS.relative_to(REPO_ROOT)}:{call.line}: {call.text}", file=sys.stderr)
        fail("mobile perf web check found openPersistent call without password argument")

    intentional_negative = []
    unexpected_ephemeral = []
    for call in ephemeral_calls:
        if len(call.args) >= 2:
            continue
        line = line_text(source, call.line)
        expected_negative = (
            call.args == ("'ephemeral-missing-password'",)
            and "expectRejects('openEphemeral missing password'" in line
        )
        if expected_negative:
            intentional_negative.append(call)
        else:
            unexpected_ephemeral.append(call)

    if len(intentional_negative) != 1:
        fail("mobile perf web check must contain exactly one intentional openEphemeral missing-password rejection probe")
    if unexpected_ephemeral:
        for call in unexpected_ephemeral:
            print(f"{APP_JS.relative_to(REPO_ROOT)}:{call.line}: {call.text}", file=sys.stderr)
        fail("mobile perf web check found openEphemeral call without password argument outside the intentional misuse test")


def main() -> int:
    if not APP_JS.is_file():
        fail(f"missing browser benchmark app: {APP_JS.relative_to(REPO_ROOT)}")
    if not SERVER_RS.is_file():
        fail(f"missing mobile perf host: {SERVER_RS.relative_to(REPO_ROOT)}")

    app_js = APP_JS.read_text(encoding="utf-8")
    server_rs = SERVER_RS.read_text(encoding="utf-8")

    server_requirements = (
        ('src="/app.js"', "external browser benchmark script"),
        ('include_str!("../web/app.js")', "host serves the browser benchmark script"),
        ("/pkg-health", "WASM package health endpoint"),
        ('env!("CARGO_MANIFEST_DIR")', "runtime-independent WASM pkg path"),
        ('data-action="multi-tab"', "multi-tab concurrency button"),
    )
    for needle, description in server_requirements:
        require_text(server_rs, needle, description, SERVER_RS)

    app_requirements = (
        ("ensureWasmPackageAvailable", "WASM package preflight check"),
        ("WASM_JS_PATH", "centralized WASM JS path"),
        ("WASM_BG_PATH", "centralized WASM binary path"),
        ("openEphemeral(EPHEMERAL_PROFILE, STATE_PASSWORD)", "passworded ephemeral benchmark open"),
        ("openPersistent(PERSISTENT_PROFILE, STATE_PASSWORD)", "passworded persistent benchmark open"),
        ("openPersistent(RESTORE_PROFILE, STATE_PASSWORD)", "passworded restore-profile open"),
        ("openEphemeral(`${EPHEMERAL_PROFILE}-persistence-peer-", "separate ephemeral peer for persistent send/receive validation"),
        ("peer.replyHandshake(offer)", "persistent-suite responder produces RESP"),
        ("hydra.finishHandshake(answer)", "persistent-suite initiator produces FINISH"),
        ("peer.acceptHandshakeFinish(finish)", "persistent-suite responder authenticates FINISH"),
        ("received = peer.receive(packet) || received;", "persistent suite receives with peer session"),
        ("await hydra.flush()", "explicit dirty-state flush in persistence suite"),
        ("exportBackup(BACKUP_PASSWORD)", "backup export benchmark coverage"),
        ("verifyBackup(backup, BACKUP_PASSWORD)", "passworded backup verification benchmark coverage"),
        ("importBackup(backup, BACKUP_PASSWORD)", "backup import benchmark coverage"),
        ("importBackup must mark restored persistent state dirty until explicit flush", "backup restore dirty-state boundary coverage"),
        ("navigator.storage.estimate", "quota estimate probe"),
        ("QuotaExceededError", "user-facing quota error path"),
        ("runApiMisuseGuard", "browser misuse regression coverage"),
        ("runMultiTabConcurrencyProbe", "multi-tab stale-writer regression coverage"),
        ("browser-wasm-indexeddb-multi-tab-concurrency", "multi-tab CAS result payload"),
        ("stale tab flush must be rejected instead of using last-writer-wins", "multi-tab stale flush rejection"),
        ("WasmHydra.browserLifecycleStatus", "browser lifecycle status probe"),
        ("WasmHydra.requestPersistentStorage", "persistent storage request probe"),
        ("IndexedDB stores opaque encrypted HYDRA snapshot bytes", "opaque-byte storage note"),
        ("expectRejects('openEphemeral missing password'", "intentional missing-password misuse probe"),
    )
    for needle, description in app_requirements:
        require_text(app_js, needle, description, APP_JS)

    for needle, description in (
        ("localStorage.", "HYDRA state must not read/write localStorage"),
        ("localStorage[", "HYDRA state must not read/write localStorage"),
        ("openDefault", "removed durable-looking WASM alias"),
        ("WasmHydra.open(", "ambiguous WASM open alias"),
    ):
        forbid_text(app_js, needle, description, APP_JS)

    check_passworded_open_calls(app_js)
    print("mobile perf web checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
