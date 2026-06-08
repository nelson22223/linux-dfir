#!/usr/bin/env python3
"""Build a compact analysis pack from linux_dfir ai/evidence.jsonl."""

from __future__ import annotations

import argparse
import collections
import heapq
import json
import os
from pathlib import Path
from typing import Any


FACET_KEYWORDS = {
    "sessions": ("session", "auth", "login", "sudo", "wtmp", "btmp", "lastlog"),
    "persistence": (
        "persistence",
        "cron",
        "pam",
        "systemd",
        "autorun",
        "profile",
        "sudoers",
        "authorized",
        "xdg",
        "rc.local",
        "init.d",
        "upstart",
    ),
    "network": (
        "network",
        "socket",
        "flow",
        "dns",
        "route",
        "arp",
        "neighbor",
        "dhcp",
        "proxy",
        "tunnel",
        "firewall",
        "conntrack",
    ),
    "process": ("process", "lineage", "procfs"),
    "files_packages": ("file", "package", "hash", "integrity", "suid", "sgid", "recent"),
    "kernel": ("kernel", "module", "rootkit", "sysctl", "taint", "lockdown", "lsm"),
    "logs": ("log", "journal", "audit", "syslog"),
    "container": ("container", "cgroup", "namespace", "podman", "docker", "kubernetes", "cri-o"),
}

IMPORTANT_KEYS = {
    "absent_reason",
    "actual_md5",
    "append_only",
    "category",
    "cmdline",
    "command",
    "commands",
    "container_id",
    "cwd",
    "entity_id",
    "entity_type",
    "event_type",
    "exe",
    "exists",
    "expected_md5",
    "file_exists",
    "flow_kind",
    "gid",
    "hash_available",
    "immutable",
    "item_type",
    "line_number",
    "lineage_key",
    "manager",
    "message",
    "mode",
    "mtime",
    "package_conffile",
    "package_key",
    "package_name",
    "parent_key",
    "path",
    "pid",
    "ppid",
    "process_name",
    "process_session_id",
    "raw_copy_ref",
    "remote_addr",
    "remote_address",
    "remote_port",
    "script_path",
    "service",
    "session_key",
    "sha256",
    "socket",
    "source_file",
    "target_path",
    "target_user",
    "timestamp",
    "tty",
    "uid",
    "unit",
    "user",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a compact linux_dfir analysis pack.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--collector-output", help="Collector output directory containing ai/evidence.jsonl")
    source.add_argument("--evidence", help="Path to ai/evidence.jsonl")
    parser.add_argument("--out", required=True, help="Output directory for the analysis pack")
    parser.add_argument("--max-examples", type=int, default=80, help="Max representative records per facet")
    parser.add_argument("--max-string", type=int, default=500, help="Max string length inside samples")
    parser.add_argument("--max-list", type=int, default=12, help="Max list length inside samples")
    parser.add_argument("--max-dict", type=int, default=40, help="Max dict keys inside samples")
    return parser.parse_args()


def evidence_path(args: argparse.Namespace) -> Path:
    if args.evidence:
        return Path(args.evidence)
    return Path(args.collector_output) / "ai" / "evidence.jsonl"


def shrink(value: Any, max_string: int, max_list: int, max_dict: int) -> Any:
    if isinstance(value, str):
        if len(value) > max_string:
            return value[:max_string] + "...<truncated>"
        return value
    if isinstance(value, list):
        result = [shrink(item, max_string, max_list, max_dict) for item in value[:max_list]]
        if len(value) > max_list:
            result.append({"truncated_items": len(value) - max_list})
        return result
    if isinstance(value, dict):
        items = list(value.items())
        selected = items[:max_dict]
        result = {str(k): shrink(v, max_string, max_list, max_dict) for k, v in selected}
        if len(items) > max_dict:
            result["_truncated_keys"] = len(items) - max_dict
        return result
    return value


def compact_data(data: Any, args: argparse.Namespace) -> Any:
    if not isinstance(data, dict):
        return shrink(data, args.max_string, args.max_list, args.max_dict)
    selected: dict[str, Any] = {}
    for key in sorted(data):
        if key in IMPORTANT_KEYS or any(token in key for token in ("time", "owner", "exec", "remote", "source")):
            selected[key] = data[key]
    if not selected:
        for key in list(data)[:20]:
            selected[key] = data[key]
    return shrink(selected, args.max_string, args.max_list, args.max_dict)


def record_facets(stream: str, collector: str, record_type: str, data: Any) -> list[str]:
    haystack = " ".join([stream, collector, record_type])
    if isinstance(data, dict):
        for key in ("category", "item_type", "entity_type", "event_type", "manager", "path", "source_file"):
            if key in data:
                haystack += " " + str(data[key])
    haystack = haystack.lower()
    facets = []
    for facet, keywords in FACET_KEYWORDS.items():
        if any(keyword in haystack for keyword in keywords):
            facets.append(facet)
    return facets or ["other"]


def score_record(rec: dict[str, Any], data: Any) -> int:
    score = 0
    stream = str(rec.get("stream", ""))
    record_type = str(rec.get("record_type", ""))
    if isinstance(data, dict):
        if data.get("exists") is True:
            score += 8
        if data.get("exists") is False:
            score -= 4
        if data.get("absent_reason"):
            score -= 2
        for key in ("command", "commands", "cmdline", "socket", "remote_addr", "remote_address", "path", "sha256"):
            if data.get(key):
                score += 3
        if data.get("source_file") or data.get("raw_copy_ref"):
            score += 1
    if "error" in stream or "error" in record_type:
        score -= 3
    if "status" in record_type:
        score -= 2
    return score


def push_sample(heap: list[tuple[int, int, dict[str, Any]]], score: int, line_no: int, sample: dict[str, Any], limit: int) -> None:
    item = (score, line_no, sample)
    if len(heap) < limit:
        heapq.heappush(heap, item)
        return
    if item > heap[0]:
        heapq.heapreplace(heap, item)


def update_time_range(value: Any, time_range: dict[str, str | None], non_epoch_time_range: dict[str, str | None]) -> None:
	if not isinstance(value, str) or "T" not in value:
		return
	current_min = time_range["min"]
	current_max = time_range["max"]
	if current_min is None or value < current_min:
		time_range["min"] = value
	if current_max is None or value > current_max:
		time_range["max"] = value
	if value < "2000-01-01T00:00:00Z":
		return
	current_min = non_epoch_time_range["min"]
	current_max = non_epoch_time_range["max"]
	if current_min is None or value < current_min:
		non_epoch_time_range["min"] = value
	if current_max is None or value > current_max:
		non_epoch_time_range["max"] = value


def collect_value_counters(data: Any, counters: dict[str, collections.Counter[str]]) -> None:
    if not isinstance(data, dict):
        return
    for key in ("user", "target_user", "remote_addr", "remote_address", "unit", "service", "package_name", "path", "flow_kind"):
        value = data.get(key)
        if value is None or value == "":
            continue
        counters[key][str(value)] += 1
    socket = data.get("socket")
    if isinstance(socket, dict):
        remote = socket.get("remote_address")
        port = socket.get("remote_port")
        if remote and remote not in ("0.0.0.0", "::", "*"):
            counters["socket_remote"][f"{remote}:{port}"] += 1


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    evidence = evidence_path(args)
    out = Path(args.out)
    facet_dir = out / "facet_samples"
    out.mkdir(parents=True, exist_ok=True)
    facet_dir.mkdir(parents=True, exist_ok=True)

    if not evidence.is_file():
        raise SystemExit(f"evidence file not found: {evidence}")

    streams: collections.Counter[str] = collections.Counter()
    collectors: collections.Counter[str] = collections.Counter()
    record_types: collections.Counter[str] = collections.Counter()
    source_paths: collections.Counter[str] = collections.Counter()
    facet_counts: collections.Counter[str] = collections.Counter()
    status_counts: collections.Counter[str] = collections.Counter()
    value_counters: dict[str, collections.Counter[str]] = collections.defaultdict(collections.Counter)
    facet_heaps: dict[str, list[tuple[int, int, dict[str, Any]]]] = collections.defaultdict(list)
    errors: list[dict[str, Any]] = []
    invalid_json: list[dict[str, Any]] = []
    time_range: dict[str, str | None] = {"min": None, "max": None}
    non_epoch_time_range: dict[str, str | None] = {"min": None, "max": None}

    total = 0
    with evidence.open("r", encoding="utf-8", errors="replace") as handle:
        for line_no, line in enumerate(handle, 1):
            total += 1
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as exc:
                invalid_json.append({"line": line_no, "error": str(exc)})
                continue

            stream = str(rec.get("stream", ""))
            collector = str(rec.get("collector", ""))
            record_type = str(rec.get("record_type", ""))
            data = rec.get("data", {})
            streams[stream] += 1
            collectors[collector] += 1
            record_types[record_type] += 1

            source_path = rec.get("source_path")
            if source_path:
                source_paths[str(source_path)] += 1
            if isinstance(data, dict):
                update_time_range(data.get("timestamp"), time_range, non_epoch_time_range)
                update_time_range(data.get("mtime"), time_range, non_epoch_time_range)
                update_time_range(data.get("ctime"), time_range, non_epoch_time_range)
                if data.get("exists") is False:
                    status_counts["exists_false"] += 1
                if data.get("absent_reason"):
                    status_counts["absent_reason"] += 1
                if data.get("issues"):
                    status_counts["records_with_issues"] += 1
            update_time_range(rec.get("timestamp"), time_range, non_epoch_time_range)

            if stream == "errors" or "error" in record_type:
                if len(errors) < 200:
                    errors.append(
                        {
                            "line": line_no,
                            "stream": stream,
                            "collector": collector,
                            "record_type": record_type,
                            "source_path": source_path,
                            "data": compact_data(data, args),
                        }
                    )

            collect_value_counters(data, value_counters)
            facets = record_facets(stream, collector, record_type, data)
            sample = {
                "evidence_line": line_no,
                "stream": stream,
                "collector": collector,
                "record_type": record_type,
                "source_path": source_path,
                "source_type": rec.get("source_type"),
                "source_trust": rec.get("source_trust"),
                "raw_artifact_ref": rec.get("raw_artifact_ref") or (data.get("raw_copy_ref") if isinstance(data, dict) else None),
                "data": compact_data(data, args),
            }
            score = score_record(rec, data)
            for facet in facets:
                facet_counts[facet] += 1
                push_sample(facet_heaps[facet], score, line_no, sample, args.max_examples)

    overview = {
        "evidence_path": str(evidence),
        "evidence_bytes": evidence.stat().st_size,
        "evidence_mib": round(evidence.stat().st_size / 1024 / 1024, 2),
        "total_lines": total,
		"invalid_json_count": len(invalid_json),
		"time_range": time_range,
		"non_epoch_time_range": non_epoch_time_range,
        "top_streams": streams.most_common(30),
        "top_collectors": collectors.most_common(30),
        "top_record_types": record_types.most_common(30),
        "top_source_paths": source_paths.most_common(30),
    }
    quality = {
        "invalid_json": invalid_json[:200],
        "status_counts": dict(status_counts),
        "error_examples": errors,
        "error_example_count": len(errors),
    }
    facet_index = {
        "facet_counts": dict(facet_counts),
        "facet_files": {facet: f"facet_samples/{facet}.jsonl" for facet in sorted(facet_heaps)},
    }
    top_values = {key: counter.most_common(50) for key, counter in sorted(value_counters.items())}

    write_json(out / "evidence_overview.json", overview)
    write_json(out / "collection_quality.json", quality)
    write_json(out / "facet_index.json", facet_index)
    write_json(out / "top_values.json", top_values)

    for facet, heap in sorted(facet_heaps.items()):
        samples = [item[2] for item in sorted(heap, reverse=True)]
        with (facet_dir / f"{facet}.jsonl").open("w", encoding="utf-8") as handle:
            for sample in samples:
                handle.write(json.dumps(sample, ensure_ascii=False, sort_keys=True) + "\n")

    context = [
        "# Linux DFIR Analysis Pack",
        "",
        f"- Evidence: `{evidence}`",
        f"- Lines: {total}",
        f"- Size: {overview['evidence_mib']} MiB",
        f"- Invalid JSON: {len(invalid_json)}",
		f"- Time range: {time_range['min']} to {time_range['max']}",
		f"- Non-epoch time range: {non_epoch_time_range['min']} to {non_epoch_time_range['max']}",
        "",
        "## Top Collectors",
    ]
    context.extend(f"- {name}: {count}" for name, count in collectors.most_common(12))
    context.extend(["", "## Top Streams"])
    context.extend(f"- {name}: {count}" for name, count in streams.most_common(20))
    context.extend(["", "## Facets"])
    context.extend(f"- {name}: {count} records, samples in `facet_samples/{name}.jsonl`" for name, count in facet_counts.most_common())
    context.extend(
        [
            "",
            "## Suggested Reading Order",
            "1. `collection_quality.json`",
            "2. `facet_samples/sessions.jsonl`",
            "3. `facet_samples/persistence.jsonl`",
            "4. `facet_samples/network.jsonl`",
            "5. `facet_samples/process.jsonl`",
            "6. `facet_samples/files_packages.jsonl`",
            "7. `facet_samples/kernel.jsonl`",
            "",
            "Use `evidence_line` to fetch exact source rows from the original JSONL when a finding needs proof.",
        ]
    )
    (out / "ai_context.md").write_text("\n".join(context) + "\n", encoding="utf-8")

    print(json.dumps({"out": str(out), "lines": total, "invalid_json": len(invalid_json), "facets": dict(facet_counts)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
