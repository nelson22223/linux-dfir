# Human Report Contract

The report is a human-readable incident response document. The required report output is one file:

```text
report.md
```

Machine-readable files are optional supporting artifacts. They are not the report. If generated, put them under `support/` so the output directory stays clear:

```text
support/report_data.json
support/timeline.jsonl
support/findings.json
support/entity_graph.json
support/collector_quality.json
support/evidence_refs.jsonl
```

Never modify the collector output. Write the report and optional support files into a separate analysis directory, for example `/tmp/linux-dfir-report`.

## report.md

Write for responders and customers. Avoid dumping raw JSON. Use tables, short finding cards, timelines, and evidence references.

Use this section order:

1. Executive Summary
2. Scope And Collection Quality
3. Key Findings
4. Timeline Highlights
5. Account And Session Activity
6. Process And Command Execution
7. Network Exposure And External Connections
8. Persistence
9. File And Package Integrity
10. Kernel And Rootkit Clues
11. Container Context
12. Scenario-Specific Analysis
13. Evidence Appendix
14. Recommended Next Actions

Every finding or important statement should cite evidence as `[E:<line>]`. If exact lines were not yet extracted, mark the report as draft.

## Finding Card

Use this shape inside `report.md`:

```text
### F-001 Finding Title

- Category: sessions | persistence | network | process | files/packages | kernel | container | correlation
- Confidence: low | medium | high
- Summary: one short paragraph
- Evidence: [E:1201], [E:1686]
- Related entities: user/process/file/package/socket/unit/container where available
- Counter-evidence / gaps: facts that weaken or limit the conclusion
- Recommended validation: concrete next check
```

## Evidence Appendix

At the end of `report.md`, list cited evidence in a compact table:

```text
| Evidence | Stream | Collector | Source | Note |
|---|---|---|---|---|
| [E:1201] | facts/process_lineage | process | /proc/1/stat | Process lineage context |
```

Use `scripts/extract_evidence_lines.py` to create `support/evidence_refs.jsonl` when exact source rows are needed for auditability.

## Optional Support Files

These files are useful for automation, review, or UI rendering, but they must not replace the human report.

### support/report_data.json

Machine-readable mirror of the report structure.

### support/findings.json

Structured finding cards for downstream tools.

### support/timeline.jsonl

Normalized timeline events referenced by `report.md`.

### support/entity_graph.json

Nodes and edges used to explain relationships in the report.

### support/collector_quality.json

Copy or refine the analysis pack's collection quality facts. Keep collection limitations separate from security conclusions.

### support/evidence_refs.jsonl

Exact extracted source lines used in findings. Each line should include `_evidence_line`, original envelope fields, and original `data`.
