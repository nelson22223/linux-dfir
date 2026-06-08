---
name: linux-dfir-analyzer
description: Analyze Linux DFIR collector outputs from the linux_dfir Go ATTK project. Use when Codex needs to triage or report on a collector output directory, ai/evidence.jsonl, manifest.json, archive_summary.json, or a packaged linux_dfir evidence tarball without loading the full JSONL into model context.
---

# Linux DFIR Analyzer

## Core Rule

Do not read the full `ai/evidence.jsonl` into context. Always build a compact analysis pack first, then inspect focused facet files and exact evidence lines as needed.

The collector records facts only. Analysis, findings, confidence, severity, and response recommendations belong in this skill's output, and every conclusion must cite evidence line numbers plus source metadata.

## Workflow

Run two layers:

- **Layer 1: Evidence preparation.** Build the compact analysis pack, classify records into facets, compute counts and quality signals, and preserve `evidence_line` for source lookup.
- **Layer 2: DFIR analysis.** Apply the module playbooks, run cross-facet correlation, adapt to any user-provided suspected scenario, then write the stable report outputs.

1. Locate the collector output:
   - Directory form: `<output>/ai/evidence.jsonl`
   - Archive form: extract the tarball to a temporary directory first.

2. Build the compact analysis pack:

```bash
python3 skills/linux-dfir-analyzer/scripts/build_analysis_pack.py \
  --collector-output /path/to/output \
  --out /tmp/linux-dfir-analysis-pack
```

Use `--evidence /path/to/ai/evidence.jsonl` if only the JSONL file is available.

3. Read these files first:
   - `ai_context.md`: small model-facing overview.
   - `evidence_overview.json`: counts, size, top streams, top collectors, time range.
   - `collection_quality.json`: errors, absent/status facts, invalid JSON, permission issues.
   - `facet_index.json`: available facet packs and their counts.

4. Analyze by facet instead of by raw stream:
   - `facet_samples/sessions.jsonl`: login, sudo, auth, wtmp/btmp/lastlog derived facts.
   - `facet_samples/persistence.jsonl`: systemd, cron, PAM, shell profile, SSH, rc/init, XDG.
   - `facet_samples/network.jsonl`: socket, flow, DNS, route, proxy, tunnel, DHCP, counters.
   - `facet_samples/process.jsonl`: process entities, process lineage, cwd/exe/cmdline.
   - `facet_samples/files_packages.jsonl`: file metadata, hashes, package ownership/integrity.
   - `facet_samples/kernel.jsonl`: modules, kernel security, kernel consistency.
   - `facet_samples/logs.jsonl`: auth/syslog/audit/journal events.
   - `facet_samples/container.jsonl`: container, cgroup, namespace context.
   - `facet_samples/browser.jsonl`: browser history, downloads, cookies, bookmarks.
   - `facet_samples/quality.jsonl`: errors, absent facts, permission limits, skipped/status records.
   - `facet_samples/timeline.jsonl`: collector timeline and time-ordered supporting facts.

5. When a finding needs proof, cite:
   - `evidence_line`
   - `stream`
   - `collector`
   - `source_path`
   - `raw_artifact_ref` if present

   To fetch exact source rows:

```bash
python3 skills/linux-dfir-analyzer/scripts/extract_evidence_lines.py \
  --collector-output /path/to/output \
  --lines 1201,1686,272756 \
  --out /tmp/linux-dfir-analysis-pack/evidence_refs.jsonl
```

6. If the analysis pack indicates missing permission, absent logs, invalid JSON, or excessive truncation, include this in the collection quality section rather than treating it as compromise.

7. For Layer 2 analysis:
   - Read `references/analysis-playbooks.md`.
   - If the user provides a suspected scenario, run the matching scenario playbook first, then still complete the baseline module checks.
   - Read `references/report-contract.md` before writing the human report.

## Output Shape

Produce one human-readable report: `report.md`. Optional machine-readable support files may be written under `support/`, but they are not the report.

Keep the raw collector output immutable. Write parser outputs to a separate analysis directory.

## References

Read:

- `references/evidence-facets.md` for Layer 1 facet definitions.
- `references/analysis-playbooks.md` for Layer 2 module, correlation, and scenario analysis.
- `references/report-contract.md` for the human report format and optional support artifacts.
