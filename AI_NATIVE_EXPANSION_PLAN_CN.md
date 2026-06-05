# AI 原生 DFIR 升级路线索引

更新时间：2026-06-05

本文保留为总索引。为避免混淆，“采集器事实采集”和“parser/AI 分析”已经拆成两个独立文档维护：

- `GO_ATTK_COLLECTOR_ROADMAP_CN.md`：Go ATTK collector 本身路线，只记录采集、轻量结构化、证据链、打包和验收；不做风险判断。
- `PARSER_REQUIREMENTS_CN.md`：parser / AI agent 需求池，记录后续分析、关联、判断、报告、置信度和输出物设计。

固定原则不变：collector 只做事实采集，不在工具内做风险判断；所有 AI 结构化事实进入单一 `ai/evidence.jsonl`；legacy/raw 继续用于复核和证据保全。

## 当前基线

- 原版 ATTK 非扫描采集 legacy 对比已补齐到 `missing_or_partial=0`。
- Go 版保留 legacy 文本/raw 输出，并额外提供 AI 原生结构化输出。
- 登录/认证关键 raw 已结构化：`wtmp/btmp/lastlog -> facts/login_events`，auth/syslog classic 和 ISO8601 行进入 `facts/auth_events` / `facts/log_events`。
- 当前可以认为：非扫描采集面已完成原始能力复刻，并具备 AI 原生分析入口。

## 文档分工

| 文档 | 维护内容 | 当前状态 |
|---|---|---|
| `GO_ATTK_COLLECTOR_ROADMAP_CN.md` | collector 主 roadmap：已完成基线、当前缺失、优先级、后续 phase、stream、验收 | 当前主文档 |
| `PARSER_REQUIREMENTS_CN.md` | parser 输入契约、实体模型、分析能力、报告输出、对 collector 的字段需求 | 需求收集中 |
| `PHASE_STATUS_CN.md` | Phase 1-14 历史执行留档、gate、VM 产物和补测记录 | 历史留档 |
| `PERSISTENCE_NETWORK_COVERAGE_MATRIX_CN.md` | P0 Persistence/Network 已完成覆盖矩阵和缺口 | 历史参考 |

## 当前建议节奏

1. Collector Phase B：会话观察
   - Collector 只输出可关联事实字段。
   - Parser 后续负责建立登录、sudo、进程、文件和网络链路。

2. Collector Phase C1：包完整性事实
   - Collector 输出 dpkg/rpm 校验事实。
   - Parser 后续判断命令替换、系统文件篡改和影响面。

3. Collector Phase C2：内核一致性观察
   - Collector 输出 proc/sysfs/module/package/signature/taint 一致性事实。
   - Parser 后续判断 rootkit 线索。

4. Parser Phase 0：Evidence loader + index
   - 当前仅收集需求，暂不实现。
   - 先定义 line ref、source ref、entity merge、timeline normalization。

## 边界提醒

- 不在 collector 内输出 severity、risk、verdict、malicious、suspicious 结论。
- 不因为 AI 输出增强而删除 legacy/raw 复核产物。
- 不把大型 raw 文本全文塞入 JSONL；JSONL 保留结构化事实、关键字段、hash、raw ref 和必要 excerpt。
- Parser 可以输出判断和风险，但必须明确这是 parser 结论，且每条结论都要引用 collector evidence。
