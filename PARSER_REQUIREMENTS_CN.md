# DFIR Parser / AI Agent 需求池

更新时间：2026-06-05

本文维护 collector 下游 parser / AI agent 的需求。Parser 当前尚未开始实现，本文件先收集目标、输入契约、分析任务、输出形态和对 collector 的字段需求。Collector 路线见 `GO_ATTK_COLLECTOR_ROADMAP_CN.md`。

## 角色边界

Parser / AI agent 负责：

- 读取 collector 输出的 `ai/evidence.jsonl`、`ai/manifest.json`、`ai/artifact_index.json` 和必要 raw/legacy 引用。
- 建立实体图、时间线、会话链、进程链、网络链、持久化链。
- 做判断、归因、置信度、优先级、报告生成。
- 输出给人的应急响应报告、复核清单和下一步建议。

Parser / AI agent 不负责：

- 在目标主机上二次采集。
- 修改证据或重写 collector 输出。
- 依赖 legacy 文本作为唯一输入；legacy/raw 只作为复核来源。

## 输入契约

主输入：

```text
ai/evidence.jsonl
```

辅助输入：

```text
ai/manifest.json
ai/artifact_index.json
ai/archive_summary.json
ai/raw/
legacy/
```

Parser 必须假设：

- `evidence.jsonl` 是唯一结构化证据流。
- 同一实体可能由多个 collector 观察到，需要按 `entity_id`、path、pid、inode、hash、user、timestamp 等字段合并。
- `exists=false`、`record_subtype=status`、`absent_reason` 是采集状态事实，不是异常结论。
- `source_trust` 是来源可信度，不等同于恶意置信度。
- raw/legacy 可能包含敏感信息，引用时需要脱敏或限制摘录。

## Parser 输出目标

| 输出 | 目标用户 | 内容 |
|---|---|---|
| Triage summary | 一线 IR | 主机概况、关键时间范围、重点关注对象、证据缺口 |
| Incident timeline | 分析员 | 登录、sudo、进程、网络、文件、持久化、日志事件按时间排序 |
| Entity graph | AI / 分析系统 | user、session、process、socket、file、package、service、container 的关系图 |
| Findings | 分析员 / 客户 | 可复核发现、置信度、证据引用、影响面 |
| Evidence appendix | 复核人员 | 每个结论引用的 evidence line、source_path、raw_ref、hash |
| Collector quality report | 工具维护者 | 采集缺口、权限失败、parser 无法使用的字段、重复/冲突数据 |

## AI 分析 Skill / Parser 前置层原型

当前默认 `deep` 在 Ubuntu ARM64 VM 上约产生 36 万行、300 MiB 的 `ai/evidence.jsonl`。这不适合直接放入 LLM 上下文。推荐架构是：

```text
collector output
  -> streaming preprocessor / skill script
  -> compact analysis pack
  -> AI agent 按 facet 分析
  -> 按 evidence_line 回查原始 JSONL / raw / legacy
  -> report / findings / timeline / graph
```

已新增项目内 skill 原型：

```text
skills/linux-dfir-analyzer/
  SKILL.md
  references/evidence-facets.md
  scripts/build_analysis_pack.py
  scripts/extract_evidence_lines.py
```

使用方式：

```sh
python3 skills/linux-dfir-analyzer/scripts/build_analysis_pack.py \
  --collector-output /path/to/collector-output \
  --out /tmp/linux-dfir-analysis-pack
```

在当前 VM 样本上，`build_analysis_pack.py` 可将约 300 MiB / 36 万行 JSONL 流式压缩为约 600 KiB 的分析包，耗时约 4 秒。分析包包含：

| 文件 | 作用 |
|---|---|
| `ai_context.md` | 给 AI 首读的轻量概览，包含行数、大小、top stream、top collector、facet 位置 |
| `evidence_overview.json` | 机器可读总体计数、时间范围、top source path |
| `collection_quality.json` | invalid JSON、error examples、absent/status/permission 质量事实 |
| `facet_index.json` | 每个分析面的计数和样本文件位置 |
| `top_values.json` | 常见 user、remote、unit、package、path、flow_kind 等高频值 |
| `facet_samples/*.jsonl` | sessions、persistence、network、process、files_packages、kernel、logs、container 等分面代表样本 |

设计原则：

- Parser / skill 不直接吞全量 JSONL，而是先做 streaming index 和 bounded samples。
- Compact pack 只作为分析入口，不替代原始证据；所有结论必须能回指 `evidence_line`。
- 需要复核时，用 `extract_evidence_lines.py` 根据 `evidence_line` 抽取原始 JSONL 行。
- 分析面按 DFIR 任务组织，而不是按 collector 模块组织。
- `collection_quality` 中的权限不足、日志缺失、`exists=false` 是采集事实，不直接等价于安全问题。
- 后续可以把该 skill 安装到 `~/.codex/skills`，也可以将脚本演进为独立 parser CLI。

## 首批 Parser 能力需求

### P0：证据装载与归一

目标：稳定读取 `evidence.jsonl`，构建基础索引。

需求：

- JSONL streaming parser，支持大文件。
- 按 `stream`、`collector`、`record_type` 建索引。
- 统一时间字段，保留原始时区和推断标记。
- 建立 source/ref 索引：line number、source_path、raw_artifact_ref、artifact hash。
- 对 `exists=false`、status、absent、error_event 单独分类。

依赖 collector：

- 每行稳定 envelope。
- 关键记录包含 `entity_id` 或可推导稳定 key。

### P0：会话链与登录时间线

目标：把登录、sudo、TTY、进程和日志串成事实链。

需求：

- SSH accepted/failed 聚合。
- sudo command/session open/close 聚合。
- wtmp/btmp/lastlog/utmp 与 auth log 互相印证。
- 生成候选链：remote -> user -> tty/session -> sudo -> command/process。
- 输出置信度和证据引用。

依赖 collector：

- `facts/session_observations` 或增强后的 `facts/login_events` / `facts/auth_events`。
- `entities/process` 中 start_time、ppid、tty/session/cwd/exe。

### P0：持久化链分析

目标：识别和解释持久化入口，但结论在 parser 层输出。

需求：

- systemd unit/drop-in/enabled symlink 合并。
- cron、shell profile、sudoers、SSH authorized_keys、loader、PAM、XDG autostart 聚合。
- 把持久化命令关联到文件 hash、package owner、mtime、进程/网络证据。
- 输出“发现项 + 证据链 + 复核建议”。

依赖 collector：

- systemd directives、cron command、profile command、sudoers command、authorized_keys options。
- file hash/package owner。
- raw_ref 指向原文件副本或 legacy。

### P0：命令替换 / 文件完整性分析

目标：解释系统命令、包文件、关键配置是否与包数据库一致。

需求：

- 对 `facts/package_integrity` 做聚合。
- 关联 `entities/file`、`facts/file_hashes`、`facts/file_package_owners`。
- 识别 missing/modified/config-changed/unknown-owner 等状态。
- 对关键命令路径生成复核列表。

依赖 collector：

- expected hash、actual hash、verify status、package name/version、conffile 标记。

### P0：网络外联与进程归因

目标：把 socket/flow 关联到进程、用户、二进制、包、容器。

需求：

- listener/outbound/local/remote flow 分类。
- remote IP/port、process owner、exe hash/package、cmdline/cwd/container 聚合。
- DNS/resolv/hosts/proxy/tunnel config 与连接事实关联。
- 输出外联实体列表和证据链。

依赖 collector：

- `facts/network_flows`、`entities/socket` owners、`facts/dns_config`、`facts/network_persistence`。

### P1：Kernel / rootkit 线索分析

目标：基于一致性事实做 rootkit 线索解释。

需求：

- 对 `/proc/modules`、`/sys/module`、module file、package owner、signature、taint 做一致性分析。
- 对 process/socket/cgroup/task 不一致事实做聚合。
- 输出 rootkit 线索，而不是依赖 collector verdict。

依赖 collector：

- `facts/kernel_consistency`、`facts/kernel_security`、module hash/package/signature。

### P1：Journal / service 行为分析

目标：把 systemd journal 与持久化、进程和网络事实合并。

需求：

- unit restart/failure/start/stop 事件聚合。
- journal pid/unit 与 process/systemd unit 关联。
- 服务启动时间和文件 mtime/hash 关联。

依赖 collector：

- `facts/journal_events`，包含 unit、pid、uid、boot_id、priority、timestamp。

## Parser 数据模型草案

建议内部对象：

```text
Host
User
Session
Process
Socket / Flow
File
Package
PersistenceEntry
ServiceUnit
KernelModule
Container
EvidenceRef
Finding
TimelineEvent
```

核心原则：

- 所有 Finding 必须能回指 `EvidenceRef`。
- 所有判断必须有置信度和反证/缺口说明。
- 同一事实来自多个 stream 时做 union merge，不丢 source。
- Parser 可以输出风险/严重性，但必须明确这是 parser 结论，不回写 collector JSONL。

## 报告输出草案

建议至少支持：

```text
report.md
report.json
timeline.jsonl
findings.json
entity_graph.json
collector_quality.json
```

报告结构：

1. 摘要
2. 主机与采集质量
3. 关键发现
4. 攻击时间线
5. 登录与账户活动
6. 进程与命令执行
7. 网络外联
8. 持久化
9. 文件与包完整性
10. Kernel/rootkit 线索
11. 容器/云环境
12. 证据附录
13. 建议后续动作

## 需要 Collector 继续补齐的字段

| Parser 需求 | Collector 字段 |
|---|---|
| 登录链路 | stable session key、TTY、remote、pid、sudo target_user、command cwd |
| 命令替换判断 | expected hash、actual hash、package verify status、conffile 标记 |
| rootkit 线索 | proc/sysfs/module/package/signature/taint 一致性事实 |
| 外联归因 | flow -> pid/fd -> process -> exe hash/package/container |
| 持久化解释 | ExecStart/cron/profile/sudoers/authorized_keys/loader/PAM 结构化命令字段 |
| 时间线排序 | 统一 timestamp、time_inferred、timezone/source file mtime |
| 证据引用 | evidence line id、raw_ref、source_path、artifact hash |

## 暂不实现但记录的能力

- 多主机关联和横向移动图谱。
- IOC enrichment / threat intel 查询。
- YARA/osquery 规则管理。
- 自动生成客户报告模板。
- 与工单系统、飞书文档、知识库联动。

这些能力应等单主机 parser 稳定后再展开。
