#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOTS = (Path("crates"), Path("examples"), Path("qa/tests"))
OUTPUT = Path("target/test-quality/generic-is-err.txt")
GENERIC_ALLOWLIST = Path("qa/test-quality/generic-is-err-allowlist.tsv")

TEST_FILE_MAX_LINES = 300


def is_test_path(path: Path) -> bool:
    text = path.as_posix()
    return (
        text.startswith("qa/tests/")
        or "/tests/" in text
        or text.endswith("/tests.rs")
        or text.endswith("_tests.rs")
        or text.endswith("/test_support.rs")
    )


def check_run_all_dry(failures: list[str]) -> None:
    central = Path("qa/ci/run_all.py")
    cli = Path("qa/ci/lib/run_all_cli.py")
    wrappers = (Path("qa/ci/check-all.sh"), Path("qa/ci/check-all.ps1"))
    for path in (central, cli, *wrappers):
        if not path.is_file():
            failures.append(f"shared run-all component missing: {path}")
    for path, ceiling in ((central, 300), (cli, 200), (wrappers[0], 30), (wrappers[1], 40)):
        if path.is_file():
            lines = len(path.read_text(encoding="utf-8").splitlines())
            if lines > ceiling:
                failures.append(f"run-all DRY component exceeds {ceiling} lines: {path} ({lines})")
    for wrapper in wrappers:
        if wrapper.is_file():
            text = wrapper.read_text(encoding="utf-8")
            if "run_all.py" not in text:
                failures.append(f"native run-all wrapper does not delegate to shared orchestrator: {wrapper}")
            for duplicated in ("HYDRA_RUN_COVERAGE", "HYDRA_RUN_MUTATION", "HYDRA_FUZZ_MODE"):
                if duplicated in text:
                    failures.append(f"shared orchestration leaked back into native wrapper {wrapper}: {duplicated}")

TEST_ATTR = re.compile(r"#\[(?:tokio::)?test(?:\([^\]]*\))?\]")
FN = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
IGNORE = re.compile(r"#\[ignore(?:\([^\]]*\))?\]")
TRUE_ASSERT = re.compile(r"assert!\s*\(\s*true\s*\)")
FALSE_ASSERT = re.compile(r"assert!\s*\(\s*false\s*\)")
GENERIC_IS_ERR = re.compile(r"assert!\s*\([^;\n]*\.is_err\(\)\s*\)")


def rust_files() -> list[Path]:
    files: list[Path] = []
    for root in ROOTS:
        if root.exists():
            files.extend(p for p in root.rglob("*.rs") if "target" not in p.parts)
    return sorted(files)


def mask_non_code(text: str) -> str:
    out = list(text)
    i = 0
    n = len(text)
    while i < n:
        if text.startswith("//", i):
            j = text.find("\n", i)
            if j < 0:
                j = n
            for k in range(i, j):
                out[k] = " "
            i = j
            continue
        if text.startswith("/*", i):
            depth = 1
            j = i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth += 1
                    j += 2
                elif text.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            for k in range(i, min(j, n)):
                if out[k] != "\n":
                    out[k] = " "
            i = j
            continue
        if text[i] == 'r':
            h = i + 1
            while h < n and text[h] == '#':
                h += 1
            if h < n and text[h] == '"':
                hashes = h - i - 1
                end_token = '"' + ('#' * hashes)
                j = text.find(end_token, h + 1)
                j = n if j < 0 else j + len(end_token)
                for k in range(i, j):
                    if out[k] != "\n":
                        out[k] = " "
                i = j
                continue
        if text[i] == '"':
            j = i + 1
            while j < n:
                if text[j] == '\\':
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            for k in range(i, min(j, n)):
                if out[k] != "\n":
                    out[k] = " "
            i = j
            continue
        i += 1
    return "".join(out)


def matching_brace(masked: str, open_at: int) -> int | None:
    depth = 0
    for i in range(open_at, len(masked)):
        if masked[i] == "{":
            depth += 1
        elif masked[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return None


def tests_in(path: Path) -> list[tuple[str, str, int]]:
    source = path.read_text(encoding="utf-8")
    masked = mask_non_code(source)
    tests: list[tuple[str, str, int]] = []
    for attr in TEST_ATTR.finditer(masked):
        fn = FN.search(masked, attr.end())
        if not fn:
            continue
        brace = masked.find("{", fn.end())
        if brace < 0:
            continue
        close = matching_brace(masked, brace)
        if close is None:
            continue
        name = fn.group(1)
        body = source[brace + 1 : close]
        line = source.count("\n", 0, fn.start()) + 1
        tests.append((name, body, line))
    return tests


def normalized(body: str) -> str:
    body = re.sub(r"//.*?$", "", body, flags=re.M)
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
    return re.sub(r"\s+", "", body)


def obvious_evidence(body: str) -> bool:
    return bool(
        re.search(
            r"assert(?:_eq|_ne)?!|\bassert_[A-Za-z0-9_]*\s*\(|matches!|panic!|"
            r"unwrap(?:_err)?\s*\(|expect(?:_err)?\s*\(|\.is_(?:ok|err)\s*\(",
            body,
        )
    )


def simple_assert_eq_tautology(body: str) -> list[str]:
    found: list[str] = []
    for match in re.finditer(r"assert_eq!\s*\(\s*([^,\n]+?)\s*,\s*([^\n\)]+?)\s*\)", body):
        left = re.sub(r"\s+", "", match.group(1))
        right = re.sub(r"\s+", "", match.group(2))
        if left and left == right:
            found.append(match.group(0).strip())
    return found




def load_generic_allowlist(failures: list[str]) -> dict[str, str]:
    if not GENERIC_ALLOWLIST.is_file():
        failures.append(f"generic .is_err() allowlist missing: {GENERIC_ALLOWLIST}")
        return {}
    entries: dict[str, str] = {}
    for line_number, raw in enumerate(
        GENERIC_ALLOWLIST.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("|", 2)
        if len(parts) != 3 or not all(parts):
            failures.append(
                f"invalid generic .is_err() allowlist row {GENERIC_ALLOWLIST}:{line_number}"
            )
            continue
        path, test_name, rationale = parts
        key = f"{path}|{test_name}"
        if key in entries:
            failures.append(f"duplicate generic .is_err() allowlist entry: {key}")
            continue
        if len(rationale.strip()) < 20:
            failures.append(f"generic .is_err() rationale is too short: {key}")
            continue
        entries[key] = rationale.strip()
    return entries

def main() -> int:
    failures: list[str] = []
    bodies: defaultdict[str, list[str]] = defaultdict(list)
    generic: list[str] = []
    generic_keys: set[str] = set()
    total = 0
    check_run_all_dry(failures)
    generic_allowlist = load_generic_allowlist(failures)

    for path in rust_files():
        source = path.read_text(encoding="utf-8")
        if is_test_path(path):
            line_count = len(source.splitlines())
            if line_count > TEST_FILE_MAX_LINES:
                failures.append(f"test Rust file exceeds {TEST_FILE_MAX_LINES} lines: {path} ({line_count})")
        if IGNORE.search(source):
            failures.append(f"ignored test found: {path}")
        for name, body, line in tests_in(path):
            total += 1
            label = f"{path.as_posix()}:{line}:{name}"
            norm = normalized(body)
            if not norm:
                failures.append(f"empty test body: {label}")
            if TRUE_ASSERT.search(body):
                failures.append(f"tautological assert!(true): {label}")
            if FALSE_ASSERT.search(body):
                failures.append(f"unconditional assert!(false): {label}")
            for expr in simple_assert_eq_tautology(body):
                failures.append(f"tautological assert_eq in {label}: {expr}")
            if not obvious_evidence(body):
                failures.append(f"test has no observable assertion/error evidence: {label}")
            if len(norm) > 10:
                bodies[hashlib.sha256(norm.encode()).hexdigest()].append(label)
            if GENERIC_IS_ERR.search(body):
                generic.append(label)
                generic_keys.add(f"{path.as_posix()}|{name}")

    for labels in bodies.values():
        if len(labels) > 1:
            failures.append("exact duplicate test bodies: " + " | ".join(labels))

    unreviewed_generic = sorted(generic_keys - set(generic_allowlist))
    stale_generic = sorted(set(generic_allowlist) - generic_keys)
    for key in unreviewed_generic:
        failures.append(f"unreviewed generic .is_err() assertion: {key}")
    for key in stale_generic:
        failures.append(f"stale generic .is_err() allowlist entry: {key}")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    reviewed_inventory = []
    for label in generic:
        path, _line, name = label.rsplit(":", 2)
        rationale = generic_allowlist.get(f"{path}|{name}", "UNREVIEWED")
        reviewed_inventory.append(f"{label}|{rationale}")
    OUTPUT.write_text(
        "\n".join(reviewed_inventory) + ("\n" if reviewed_inventory else ""),
        encoding="utf-8",
    )
    print(
        f"Rust test-quality audit: {total} tests scanned; {len(generic)} generic .is_err() "
        "assertion test(s) explicitly reviewed"
    )
    print(f"Generic-error reviewed inventory: {OUTPUT}")
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print("Rust test-quality structural checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
