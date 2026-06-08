# Linux DFIR Collector

Go-based one-shot Linux incident response collector inspired by the original ATTK collection surface. It produces two parallel outputs:

- `legacy/`: ATTK-style human-readable files for responders.
- `ai/evidence.jsonl`: the primary structured evidence stream for AI agent analysis and report generation.

Development principles:

- Collector capability is only additive during migration and hardening: replacing an implementation path must preserve the previous evidence surface unless the old behavior is explicitly marked as compatibility-only.
- AI structured output uses one JSONL file: `ai/evidence.jsonl`. Individual evidence kinds are separated by `record_type`, `stream`, `collector`, and source metadata inside each line, not by separate module JSONL files.
- The collector only records observed facts, source metadata, and collection status. It must not assign risk labels, verdicts, severity, or analysis conclusions; report generation and judgment belong to the downstream AI agent or responder.
- When multiple collection paths observe the same entity or fact, records should be keyed by a stable identity and merged as a union of observed fields instead of emitting duplicate partial records.

## Build

```sh
go test ./...
make linux
```

Linux binaries are written to:

```text
dist/dfir-collector-linux-amd64
dist/dfir-collector-linux-arm64
dist/dfir-collector-linux-386
```

## Basic Use

```sh
./dist/dfir-collector-linux-amd64 --output /tmp/dfir-case
./dist/dfir-collector-linux-amd64 --output /tmp/dfir-case --archive
```

Useful flags:

```text
--profile quick|standard|deep|minimal-safe
--output /path/to/output
--output-mode legacy|ai|dual
--archive
--scan none|tmbrfix|yara|osquery
--clean disabled|confirm|force
--timeout 10m
```

Defaults are incident-response oriented: `--profile deep`, `--output-mode dual`, `--scan none`, and `--clean disabled`. If `--timeout` is omitted, the selected profile's `limits.timeout` is used.

## Profiles

- `minimal-safe`: low-sensitivity baseline metadata.
- `quick`: fast first-response triage.
- `standard`: host/process/network/persistence/browser/file/package/log coverage without container/scanner phase.
- `deep`: default extended coverage including container context and scanner phase.
- `phase*-...`: focused validation profiles used during implementation.

## Output

In the default `dual` output mode, every run finalizes:

```text
<output>/
  legacy/
  ai/
    evidence.jsonl
    manifest.json
    artifact_index.json
    raw/
```

AI consumers should treat `ai/evidence.jsonl` as the single structured evidence input. Each line is an envelope with `record_type`, `stream`, `collector`, source metadata, and a `data` object. Collection events, timeline records, errors, entity records, fact records, and artifact metadata all enter this one stream. The envelope owns evidence metadata; `data` should contain only collected fact fields. `manifest.json`, `artifact_index.json`, and `archive_summary.json` remain JSON control files for evidence-chain validation rather than event records. `ai/raw/` may contain copied binary/text source artifacts such as browser databases, logs, or scanner stdout/stderr.

When `--archive` is set, the collector also creates:

```text
<output>.tar.gz
<output>/ai/archive_summary.json
```

`archive_summary.json` is written after the tarball is created, so it is an external report for the package hash and is not inside the tarball.

## Scanner Plugins

Scanner plugins are optional and run after collection but before manifest finalization.

- `tmbrfix`: uses `payload/tmbrfix`, records executable hash/type, and only executes on compatible Linux i386/amd64 runtime.
- `yara` and `osquery`: looked up via `PATH`; absent tools are recorded as skipped/absent evidence.
- Cleaning is never enabled by default. Only `--clean confirm` or `--clean force` can add tmbrfix clean arguments.

Scanner outputs go to:

```text
legacy/filescan/
ai/raw/scanners/
ai/evidence.jsonl
```

## Mac Development Notes

macOS development can validate build, fixtures, JSON/JSONL, archive, and unsupported scanner behavior. It cannot prove real Linux `/proc`, `/sys`, root-only paths, container runtime metadata, audit/journal behavior, or tmbrfix execution.

### UTM Linux VM Baseline

UTM on macOS does not expose a regular GUI snapshot manager for this project workflow, and `utmctl` has no `snapshot` subcommand. Use an offline `.utm` bundle copy as the baseline snapshot instead.

Current baseline:

```text
VM name: linux-dfir-ubuntu-arm64
Baseline copy: /Users/nel/projects/vm_images/utm_snapshots/linux-dfir-baseline-ubuntu2404-arm64-go126.utm
Latest marker: /Users/nel/projects/vm_images/utm_snapshots/latest-baseline-path.txt
```

To create or refresh this style of baseline:

```sh
# 1. Shut down cleanly from the guest or host.
ssh -i /Users/nel/projects/vm_images/linux-dfir-vm_ed25519 dfir@192.168.64.2 'sudo poweroff'

# 2. Wait until UTM reports stopped.
/opt/homebrew/bin/utmctl status linux-dfir-ubuntu-arm64

# 3. Copy the stopped VM bundle.
mkdir -p /Users/nel/projects/vm_images/utm_snapshots
rsync -a --progress \
  /Users/nel/Library/Containers/com.utmapp.UTM/Data/Documents/linux-dfir-ubuntu-arm64.utm/ \
  /Users/nel/projects/vm_images/utm_snapshots/linux-dfir-baseline-ubuntu2404-arm64-go126.utm/
```

Restore rule: stop UTM/VM first, then replace the active `.utm` bundle under `~/Library/Containers/com.utmapp.UTM/Data/Documents/` with the saved baseline copy. Do not copy a running VM bundle as a baseline.

Pending Linux VM validation:

- Real `/proc` and `/sys` success paths.
- Debian/Ubuntu and RHEL-family logs/packages.
- Docker/containerd/Podman/CRI-O/Kubernetes container paths.
- Linux amd64/arm64/386 runtime smoke.
- tmbrfix i386/amd64 32-bit compatibility smoke.
- Real YARA/osquery execution, permissions, and timeout behavior.

当前采集器路线图见 `GO_ATTK_COLLECTOR_ROADMAP_CN.md`。`PHASE_STATUS_CN.md` 是 Phase 1-14 的历史执行留档，保留 gate、Linux VM 检查清单和历史产物路径。

## 路线图

- `GO_ATTK_COLLECTOR_ROADMAP_CN.md`：采集器主路线图。维护已完成基线、当前采集缺口、优先级、后续 Go ATTK 采集 phase 和“只采事实”的边界。
- `PARSER_REQUIREMENTS_CN.md`：下游 parser / AI agent 需求池。Parser 当前尚未开始实现，本文先收集分析、关联、报告、置信度和证据引用需求。
