# Standard Core Output Gate

生成时间：2026-06-03

## 范围

本 gate 针对 `standard` profile 中 quick 之外的基础模块：

- `disk`
- `time`
- `kernel`
- `packages`
- `logs`
- `files`
- `browser`

## 原则

1. `ai/evidence.jsonl` 仍是唯一 AI JSONL 文件；所有结构化证据通过 `stream` 字段区分。
2. 新增或优化模块不得继续写 `parsed/*` stream。旧命令解析语义应替换为：
   - `entities/*`：主机上的实体，如文件、包、kernel module、browser profile。
   - `facts/*`：实体上的事实，如 hash、mount、package ownership、log event。
   - `artifacts/*`：原始日志/DB/文件副本的元数据。
3. 工具只采集事实，不输出风险、严重性、verdict 或分析结论。
4. 同一稳定 identity 不重复输出 partial record；多来源信息尽量合并为一条记录或以明确 fact identity 表达。
5. 预期可能不存在的路径记录 `exists=false` fact；短生命周期 `/proc` race 不污染 `errors`。
6. legacy 产物保留，作为人工复核和 ATTK 兼容面。

## 本轮标准输出目标

| 模块 | 旧 stream | 新 stream |
|---|---|---|
| disk | `parsed/mounts` | `facts/mounts` |
| disk | `parsed/mountinfo` | `facts/mountinfo` |
| time | `parsed/time` | `facts/time` |
| kernel | `parsed/kernel_modules` | `entities/kernel_module` |
| kernel | `entities` | `entities/kernel_module` |
| packages | `parsed/packages` | `entities/package` |
| packages | `parsed/file_package_owners` | `facts/file_package_owners` |
| logs | `parsed/log_events` | `facts/log_events` |
| logs | `parsed/auth_events` | `facts/auth_events` |
| logs | `parsed/audit_events` | `facts/audit_events` |
| files | `parsed/files` | `entities/file` |
| files | `parsed/file_hashes` | `facts/file_hashes` |
| files | `parsed/suid_files` | `facts/suid_files` |
| files | `parsed/open_files` | `facts/open_files` |
| files | `parsed/recent_files` | `facts/recent_files` |
| files | `parsed/suspicious_files` | `facts/file_flags` |
| browser | `parsed/browser_*` | `entities/browser_profile` + `facts/browser_*` |

## 验收标准

在 Linux VM root 运行 `standard` 后：

- `find ai -name '*.jsonl' | wc -l == 1`
- `jq 'select(.stream|startswith("parsed/"))' ai/evidence.jsonl | jq -s length == 0`
- `stream=errors` 不包含短生命周期 `/proc/[pid]/exe|cwd|fd` race。
- `entities/persistence_file`、`entities/file` 等带 `entity_id` 的流不出现重复 entity id。
- 原 ATTK 相关 legacy 目录继续存在：`legacy/system`、`legacy/process`、`legacy/network`、`legacy/autorun`、`legacy/browser`、`legacy/enum`、`legacy/logs`。
- subagent review/test gate 均 PASS。
