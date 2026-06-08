#!/usr/bin/env python3
"""Extract exact evidence JSONL lines by line number."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def parse_line_set(value: str) -> set[int]:
    lines: set[int] = set()
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start = int(start_text)
            end = int(end_text)
            if start <= 0 or end < start:
                raise ValueError(f"invalid line range: {part}")
            lines.update(range(start, end + 1))
            continue
        line = int(part)
        if line <= 0:
            raise ValueError(f"invalid line number: {part}")
        lines.add(line)
    return lines


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Extract exact linux_dfir evidence lines.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--collector-output", help="Collector output directory containing ai/evidence.jsonl")
    source.add_argument("--evidence", help="Path to ai/evidence.jsonl")
    parser.add_argument("--lines", required=True, help="Comma-separated line numbers or ranges, e.g. 10,20,30-35")
    parser.add_argument("--out", help="Output JSONL path. Defaults to stdout.")
    return parser.parse_args()


def evidence_path(args: argparse.Namespace) -> Path:
    if args.evidence:
        return Path(args.evidence)
    return Path(args.collector_output) / "ai" / "evidence.jsonl"


def main() -> int:
    args = parse_args()
    evidence = evidence_path(args)
    requested = parse_line_set(args.lines)
    if not evidence.is_file():
        raise SystemExit(f"evidence file not found: {evidence}")

    found: set[int] = set()
    output_lines: list[str] = []
    with evidence.open("r", encoding="utf-8", errors="replace") as handle:
        for line_no, line in enumerate(handle, 1):
            if line_no not in requested:
                continue
            found.add(line_no)
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                rec = {"invalid_json": True, "raw_line": line.rstrip("\n")}
            rec["_evidence_line"] = line_no
            output_lines.append(json.dumps(rec, ensure_ascii=False, sort_keys=True))
            if found == requested:
                break

    missing = sorted(requested - found)
    if missing:
        raise SystemExit(f"missing evidence lines: {','.join(str(item) for item in missing)}")

    payload = "\n".join(output_lines) + ("\n" if output_lines else "")
    if args.out:
        Path(args.out).write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
