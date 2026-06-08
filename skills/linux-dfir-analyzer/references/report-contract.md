# 人读报告契约

报告是给应急响应人员、客户和复核人员阅读的中文文档。除非用户明确要求英文或中英双语，否则 `report.md` 默认使用中文输出。

必需报告输出只有一个文件：

```text
report.md
```

机器可读文件只是可选附属产物，不是报告本体。如果生成，统一放在 `support/` 下，避免混淆：

```text
support/report_data.json
support/timeline.jsonl
support/findings.json
support/entity_graph.json
support/collector_quality.json
support/evidence_refs.jsonl
```

不要修改 collector 原始输出。报告和可选附属产物应写入独立分析目录，例如 `/tmp/linux-dfir-report`。

## report.md

默认中文输出。面向应急响应人员和客户编写，避免堆砌原始 JSON。优先使用摘要、表格、短 finding 卡片、时间线和证据引用。

默认章节顺序：

1. 执行摘要
2. 范围与采集质量
3. 关键发现
4. 时间线摘要
5. 账号与登录活动
6. 进程与命令执行
7. 网络暴露与外联
8. 持久化
9. 文件与软件包完整性
10. 内核与 Rootkit 线索
11. 容器上下文
12. 场景化分析
13. 证据附录
14. 建议后续动作

每个 finding 或关键判断都应使用 `[E:<line>]` 引用证据。如果尚未抽取精确证据行，应在报告中标记为草稿。

## Finding 卡片

在 `report.md` 中使用下面的中文结构：

```text
### F-001 发现标题

- 类别：登录会话 | 持久化 | 网络 | 进程 | 文件/软件包 | 内核 | 容器 | 关联分析
- 置信度：低 | 中 | 高
- 摘要：一段简短说明
- 证据：[E:1201], [E:1686]
- 关联实体：可用时列出 user / process / file / package / socket / unit / container
- 反证或限制：削弱结论或限制判断的事实
- 建议验证：下一步可执行的复核动作
```

## 证据附录

在 `report.md` 末尾用紧凑表格列出被引用的证据：

```text
| 证据 | Stream | Collector | 来源 | 说明 |
|---|---|---|---|---|
| [E:1201] | facts/process_lineage | process | /proc/1/stat | 进程谱系上下文 |
```

需要审计级复核时，使用 `scripts/extract_evidence_lines.py` 生成 `support/evidence_refs.jsonl`。

## 可选附属产物

这些文件可用于自动化、复核或 UI 展示，但不能替代人读报告。

### support/report_data.json

报告结构的机器可读镜像。

### support/findings.json

给下游工具使用的结构化 finding 卡片。

### support/timeline.jsonl

`report.md` 引用的规范化时间线事件。

### support/entity_graph.json

用于解释报告中实体关系的节点和边。

### support/collector_quality.json

复制或整理 analysis pack 中的采集质量事实。采集限制必须与安全结论分开。

### support/evidence_refs.jsonl

finding 使用到的精确原始证据行。每行应包含 `_evidence_line`、原始 envelope 字段和原始 `data`。
