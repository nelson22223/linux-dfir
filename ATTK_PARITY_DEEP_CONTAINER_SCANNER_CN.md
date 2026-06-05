# Deep Container/Scanner Output Gate

生成时间：2026-06-03

## 范围

本 gate 针对 `deep` profile 中标准采集之外的增强模块：

- `container`
- `scanner`

## 原则

1. `ai/evidence.jsonl` 仍是唯一 AI JSONL 文件；所有结构化证据通过 `stream` 字段区分。
2. deep 模块不得继续写 `parsed/*` stream，也不得写额外模块 JSONL 文件。
3. 工具只采集事实、原始输出引用和执行状态，不输出风险、严重性、verdict 或分析结论。
4. 容器实体只写一条实体流；进程、namespace、cgroup、runtime metadata 作为事实或 artifact 元数据表达。
5. scanner 插件是可选采集源；默认 `--scan none` 只写 skipped/absent fact，不执行外部 scanner。
6. legacy 产物保留，作为人工复核和 ATTK 兼容面。

## 本轮 deep 输出目标

| 模块 | 旧 stream | 新 stream |
|---|---|---|
| container | `parsed/containers` | `entities/container` |
| container | `parsed/container_entities` | 合并到 `entities/container` |
| container | `entities` | 合并到 `entities/container` |
| container | `parsed/container_processes` | `facts/process_containers` |
| container | `parsed/process_containers` | 合并到 `facts/process_containers` |
| container | `parsed/namespaces` | `facts/namespaces` |
| container | `parsed/cgroups` | `facts/cgroups` |
| container | `parsed/runtime_metadata` | `artifacts/runtime_metadata` |
| scanner | `parsed/scanner_runs` | `facts/scanner_runs` |
| scanner | `parsed/scanner_findings` | `facts/scanner_findings` |

## 验收标准

在 Linux VM root 运行 `deep --scan none` 后：

- `find ai -name '*.jsonl' | wc -l == 1`
- `jq 'select(.stream|startswith("parsed/"))' ai/evidence.jsonl | jq -s length == 0`
- `jq 'select(.data.severity or .data.verdict or .data.risk)' ai/evidence.jsonl | jq -s length == 0`
- `entities/container`、`facts/process_containers`、`facts/namespaces`、`facts/cgroups`、`artifacts/runtime_metadata`、`facts/scanner_runs`、`facts/scanner_findings` 均存在；无容器/无 scanner 时写 `exists=false` 或 skipped fact。
- 容器实体带 `entity_type=container`，有 container id 时带稳定 `entity_id=container:<id>`。
- scanner stdout/stderr 仍保留在 `ai/raw/scanners/` 和 `legacy/filescan/`。
- legacy container 输出继续存在：`legacy/container/container_processes.out`、`legacy/container/namespaces.out`、`legacy/container/cgroups.out`、`legacy/container/container_context.out`。
- subagent review/test gate 均 PASS。
