# Linux DFIR 开发文档索引

本目录存放开发过程、路线图、能力对齐和分析侧需求文档。项目根目录只保留面向使用者的 `README.md`、源码、配置、schema 和 skill。发布压缩包不进入源码树，统一放到 GitHub Releases。

## 当前主文档

- `GO_ATTK_COLLECTOR_ROADMAP_CN.md`：采集器主路线图、当前缺口、优先级和验收标准。
- `PARSER_REQUIREMENTS_CN.md`：下游 parser / AI agent 需求池、分析编排和报告契约方向。
- `AI_NATIVE_EXPANSION_PLAN_CN.md`：AI 原生采集与分析文档的总索引。

## 历史与对齐文档

- `PHASE_STATUS_CN.md`：Phase 1-14 的历史执行留档。
- `IMPLEMENTATION_PHASE_ROADMAP_CN.md`：早期分阶段实现路线。
- `ATTK_GO_MIGRATION_PLAN_CN.md`：原版 ATTK 到 Go 版的迁移分析。
- `ATTK_ORIGINAL_GO_COMPARE_VM_20260604_CN.md`：VM 中原版 ATTK 与 Go 版对比记录。
- `ATTK_PARITY_QUICK_PERSISTENCE_CN.md`、`ATTK_PARITY_STANDARD_CORE_CN.md`、`ATTK_PARITY_DEEP_CONTAINER_SCANNER_CN.md`：分层能力对齐记录。

## 专项设计文档

- `EVIDENCE_MERGE_DESIGN_CN.md`：AI JSONL 证据合并设计。
- `PERSISTENCE_NETWORK_COVERAGE_MATRIX_CN.md`：持久化与网络外联覆盖矩阵。
- `PHASE14_E2E_CHECKLIST_CN.md`：端到端验收清单。
