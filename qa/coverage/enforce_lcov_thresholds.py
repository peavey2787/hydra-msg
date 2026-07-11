#!/usr/bin/env python3
"""Enforce HYDRA critical-path coverage thresholds from an LCOV report."""

from __future__ import annotations

import sys
from pathlib import Path


def load_manifest(path: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if len(parts) != 7:
            raise SystemExit(f"{path}:{line_no}: expected 7 pipe-separated fields")
        rows.append(
            {
                "id": parts[0],
                "class": parts[1],
                "min_line": parts[2],
                "min_branch": parts[3],
                "source": parts[4],
                "test_file": parts[5],
                "test": parts[6],
            }
        )
    if not rows:
        raise SystemExit(f"{path}: no coverage rows found")
    return rows


def parse_lcov(path: Path) -> dict[str, dict[str, int]]:
    records: dict[str, dict[str, int]] = {}
    current: dict[str, int] | None = None
    current_file: str | None = None
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if raw.startswith("SF:"):
            current_file = raw[3:]
            current = records.setdefault(
                normalize(current_file),
                {"lf": 0, "lh": 0, "brf": 0, "brh": 0},
            )
        elif current is None:
            continue
        elif raw.startswith("LF:"):
            current["lf"] += int(raw[3:])
        elif raw.startswith("LH:"):
            current["lh"] += int(raw[3:])
        elif raw.startswith("BRF:"):
            current["brf"] += int(raw[4:])
        elif raw.startswith("BRH:"):
            current["brh"] += int(raw[4:])
    return records


def normalize(path: str) -> str:
    return Path(path).as_posix().replace("\\", "/")


def find_record(records: dict[str, dict[str, int]], source: str) -> dict[str, int] | None:
    wanted = normalize(source)
    for file_name, record in records.items():
        if file_name == wanted or file_name.endswith("/" + wanted):
            return record
    return None


def percent(hit: int, found: int) -> float:
    if found == 0:
        return 100.0
    return (hit / found) * 100.0


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: enforce_lcov_thresholds.py <manifest.tsv> <report.lcov>", file=sys.stderr)
        return 2
    manifest = Path(sys.argv[1])
    report = Path(sys.argv[2])
    rows = load_manifest(manifest)
    records = parse_lcov(report)
    failures: list[str] = []
    for row in rows:
        record = find_record(records, row["source"])
        if record is None:
            failures.append(f"{row['id']}: no LCOV record for {row['source']}")
            continue
        line_pct = percent(record["lh"], record["lf"])
        branch_pct = percent(record["brh"], record["brf"])
        min_line = float(row["min_line"])
        min_branch = float(row["min_branch"])
        if line_pct + 1e-9 < min_line:
            failures.append(
                f"{row['id']}: line coverage {line_pct:.2f}% < {min_line:.2f}% for {row['source']}"
            )
        if record["brf"] == 0 and min_branch > 0:
            failures.append(f"{row['id']}: no branch data for {row['source']}")
        elif branch_pct + 1e-9 < min_branch:
            failures.append(
                f"{row['id']}: branch coverage {branch_pct:.2f}% < {min_branch:.2f}% for {row['source']}"
            )
    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    print("critical-path LCOV thresholds passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
