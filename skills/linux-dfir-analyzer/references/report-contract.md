# Stable Report Contract

Write analysis outputs into a separate directory, for example `/tmp/linux-dfir-analysis-report`. Never modify the collector output.

## Required Files

```text
report.md
report.json
timeline.jsonl
findings.json
entity_graph.json
collector_quality.json
evidence_refs.jsonl
```

## report.md

Use this section order:

1. Executive Summary
2. Collection Quality
3. Scope And Time Range
4. Key Findings
5. Timeline Highlights
6. Account And Session Activity
7. Process And Command Execution
8. Network Exposure And External Connections
9. Persistence
10. File And Package Integrity
11. Kernel And Rootkit Clues
12. Container Context
13. Scenario-Specific Analysis
14. Evidence Appendix
15. Recommended Next Actions

Every finding or important statement should cite evidence as `[E:<line>]`. If exact lines were not yet extracted, mark the report as draft.

## report.json

Use this shape:

```json
{
  "schema_version": "linux-dfir-report-v1",
  "case_summary": {
    "host": "",
    "profile": "",
    "time_range": {"start": "", "end": ""},
    "scenario": "",
    "overall_confidence": "low|medium|high"
  },
  "collection_quality": {
    "status": "ok|partial|limited",
    "limitations": [],
    "source_gaps": []
  },
  "findings": [],
  "timeline_refs": [],
  "entity_graph_ref": "entity_graph.json",
  "evidence_refs": []
}
```

## findings.json

Each finding:

```json
{
  "id": "F-001",
  "title": "",
  "category": "sessions|persistence|network|process|files_packages|kernel|container|correlation",
  "confidence": "low|medium|high",
  "summary": "",
  "evidence_lines": [],
  "entities": {
    "users": [],
    "processes": [],
    "files": [],
    "packages": [],
    "sockets": [],
    "units": [],
    "containers": []
  },
  "counter_evidence": [],
  "gaps": [],
  "recommended_validation": []
}
```

## timeline.jsonl

Each line:

```json
{
  "timestamp": "",
  "time_confidence": "observed|inferred|unknown",
  "category": "",
  "summary": "",
  "evidence_lines": [],
  "entities": {}
}
```

## entity_graph.json

Use nodes and edges:

```json
{
  "nodes": [
    {"id": "", "type": "user|session|process|file|package|socket|unit|container|host", "label": "", "evidence_lines": []}
  ],
  "edges": [
    {"source": "", "target": "", "type": "logged_in|spawned|connected_to|loads|owns|persists|runs_as|in_container", "evidence_lines": []}
  ]
}
```

## collector_quality.json

Can copy or refine the analysis pack's `collection_quality.json`, but keep collector facts separate from security conclusions.

## evidence_refs.jsonl

Store exact extracted source lines used in findings. Each line should include `_evidence_line`, original envelope fields, and original `data`.
