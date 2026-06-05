# Linux DFIR Collector Phase 执行台账

更新时间：2026-06-05

本文是 Phase 1-14 的历史执行留档。所有 phase 当前均已完成并保留 gate、验证和 Linux VM 补测记录；后续 collector 总路线、当前缺口和优先级以 `GO_ATTK_COLLECTOR_ROADMAP_CN.md` 为准。详细原始范围见 `IMPLEMENTATION_PHASE_ROADMAP_CN.md`；parser / AI agent 需求池见 `PARSER_REQUIREMENTS_CN.md`。

## 固定执行路线

| Phase | 模块 | 状态 | 说明 |
|---|---|---|---|
| Phase 1 | 工程骨架 + 输出框架 | Done | CLI、profile、`legacy/` + `ai/`、manifest、artifact index、collection log、timeline、errors、schema。 |
| Phase 2 | Host/System/User/Disk/Time | Done | 系统基础采集、users/groups、SSH host key metadata、mount/time、错误记录、文件 metadata timeline。 |
| Phase 3 | Kernel | Done | `/proc/modules`、`/sys/module`、cmdline、tainted、kernel module entities；mac 缺失路径通过，Linux 成功路径待 VM。 |
| Phase 4 | Process | Done | `/proc/[pid]` 直接采集、legacy ps/lsof 合成、env 默认不输出 values、fd readlink 失败记录；Linux 成功路径待 VM。 |
| Phase 5 | Network | Done | `/proc/net` socket/route/arp/interface、socket inode 关联 PID、hosts/resolv、firewall absent；Unix listener 过滤已加固。 |
| Phase 6 | Persistence | Done | cron、rc/init、system/user systemd、ssh、shell profile、sudoers、at、XDG autostart；私钥 redaction；legacy/autorun + AI JSONL。 |
| Phase 7 | File Enum | Done | 模块文件、打开文件、autorun 文件、SUID/SGID、tmp/recent、webroot、哈希；legacy/enum + AI JSONL。 |
| Phase 8 | Package | Done | dpkg/rpm 包清单和文件包归属；dpkg multi-arch 归一、md5sums、rpm native fallback、legacy/AI 双输出。 |
| Phase 9 | Browser/History | Done | Chrome/Chromium/Firefox Linux profile discovery、SQLite raw copy + WAL/SHM、纯 Go SQLite 解析、history/download/cookie/bookmark JSONL；mac CLI 默认 absent。 |
| Phase 10 | Logs | Done | auth/secure/syslog/messages/audit、rotated/compressed、wtmp/btmp/lastlog raw copy + `facts/login_events` 结构化、ISO8601/classic syslog 解析、JSONL/timeline；syslog 年份推断标记。 |
| Phase 11 | Container/Cgroup/Namespace | Done | Docker/containerd/Podman/Kubernetes/CRI-O cgroup/ns/runtime metadata 关联；deep 输出已收敛到 `entities/container`、`facts/*`、`artifacts/*`，真实 runtime 待 Linux VM。 |
| Phase 12 | Archive | Done | tar.gz、整包 hash、manifest finalize、archive summary；review/test gate 已通过，真实大采集归档待 Linux VM。 |
| Phase 13 | Scanner Plugins | Done | scanner 插件框架、tmbrfix payload hash/兼容性、scan none/tmbrfix/yara、archive-with-scanner；输出为 `facts/scanner_*`，不写 severity/verdict，真实 scanner 待 Linux VM。 |
| Phase 14 | End-to-End | Done | mac 侧 profile smoke、JSONL、archive、operator guide、Linux VM checklist、最终 review/test gate 已完成；真实 Linux VM runtime 待用户提供环境后补测。 |

## Subagent Gate

每个 phase 必须按以下顺序推进：

1. Dev subagent：独立做开发方案或 fork 实现，输出修改范围、测试建议和风险。
2. Main agent：集成实现、修正、运行本地测试和 CLI 验收。
3. Review subagent：独立审查，不改代码；必须输出 Blocking / Non-Blocking。
4. Test subagent：独立测试，不改代码；必须输出 pass/fail、失败命令和关键日志。
5. Main agent：只有在 review 无 blocking 且 test pass 后，才能把 phase 标记为 Done。

如果 review/test 发现 blocking，main agent 修复后必须重新跑本地测试，并重启对应 subagent 复验。

## 当前已通过门禁

| Phase | Local Verification | Dev Subagent | Review Subagent | Test Subagent | Linux VM 待测 |
|---|---|---|---|---|---|
| Phase 1 | `go test ./...`、`make linux`、Phase 1 CLI、symlink 逃逸复现 | Main + subagent review feedback integrated | PASS | PASS | 无特殊待测；Linux runtime smoke 已留到 E2E。 |
| Phase 2 | `go test ./...`、`make linux`、Phase 2 CLI、manifest/source/timeline jq | Main + subagent review feedback integrated | PASS | PASS | root Linux 下确认 `/proc/*` 成功采集、`/etc/sudoers` 成功复制 metadata、mountinfo 成功采集。 |
| Phase 3 | `go test ./...`、`make linux`、Phase 3 CLI、fake kernel source tests、mac absent records | Faraday | PASS | PASS | Linux 下确认 `/proc/modules`、`/sys/module`、cmdline、tainted、module entities、modules.dep 映射成功路径。 |
| Phase 4 | `go test ./...`、`make linux`、Phase 4 CLI、fake procfs success/race/absent/fd-entry tests | Helmholtz | PASS | PASS | Linux 下确认真实 `/proc/[pid]`、`status/cmdline/environ/exe/cwd/root/maps/fd` 成功路径、non-root permission errors、legacy ps/lsof 非空。 |
| Phase 5 | `go test ./...`、`make linux`、Phase 5 CLI、fake proc/net success、socket inode owner、mac absent records、manifest hash、JSONL parse | Raman | Meitner PASS | Ptolemy PASS | Linux 下确认真实 `/proc/net/tcp,tcp6,udp,udp6,unix,route,arp,dev,if_inet6` 成功路径、socket inode -> PID/FD、IPv4/IPv6 listener、Unix socket、legacy network 输出可读。 |
| Phase 6 | `go test ./...`、`make linux`、Phase 6 CLI、fixture root persistence success、mac absent/error、JSONL parse、private key leak scan | Hooke | Feynman PASS | Lagrange PASS | Linux 下确认真实 `/etc/cron*`、`/var/spool/cron*`、`/etc/init`、system/user systemd、sudoers、at spool、用户 `.ssh` 权限路径；systemd enabled symlink/drop-in 语义。 |
| Phase 7 | `go test ./...`、`make linux`、Phase 7 CLI、fixture root file enum success、SUID/open/recent/hash/absent tests、JSONL parse | Heisenberg + Kant | Hume PASS | Hubble PASS | Linux 下确认真实 `/proc/[pid]/fd/exe/cwd`、SUID/SGID、world-writable、tmp/dev_shm/var_tmp、webroot、deleted open files、权限失败和 hash 超限路径。 |
| Phase 8 | `go test ./internal/collectors/packages`、`go test ./...`、Phase 8 CLI、JSONL parse、legacy unavailable outputs、multi-arch dpkg fixture、`make linux` | Bernoulli | James FAIL -> Noether PASS | Ampere PASS -> Hegel PASS | Linux 下确认真实 Debian/Ubuntu `/var/lib/dpkg/status`、`.list/.md5sums` 成功路径；RHEL/CentOS/Rocky `rpm -qa`、`rpm -q --filesbypkg -a` 输出格式和文件归属准确性；root/non-root 权限失败路径。 |
| Phase 9 | `go test ./internal/collectors/browser`、`go test ./...`、Phase 9 CLI、JSONL parse、fixture SQLite/WAL/SHM/damaged DB、cookie value leak scan、`make linux` | Pauli | Galileo FAIL -> Carver PASS | Godel PASS -> Darwin PASS | Linux 下确认真实 Chrome/Chromium/Firefox profile 成功路径、其他用户权限失败、live locked DB、Firefox downloads 版本差异。 |
| Phase 10 | `go test ./internal/collectors/logs`、`go test ./...`、Phase 10 CLI、JSONL parse、gzip rotated fixture、wtmp/btmp/lastlog raw copy + login_events fixture、auth/audit/timeline fixture、Ubuntu ARM64 VM deep `--scan none` evidence 抽样 | Sartre | Boyle PASS -> Arendt PASS | Socrates PASS -> Banach PASS | RHEL `/var/log/secure/messages`、audit 权限、active rotation、超大日志/权限 denied；更多发行版的 utmp/lastlog 变体。 |
| Phase 11 | `go test ./internal/collectors/container`、`go test ./...`、Phase 11 CLI、JSONL parse、runtime metadata fixture、cgroup/ns fixture、mac/no-`/proc` metadata guard、`make linux` | Maxwell PASS | Tesla FAIL -> PASS | Dirac FAIL -> PASS | Linux 下确认真实 Docker/containerd/Podman/CRI-O/Kubernetes cgroup v1/v2、namespace inode、runtime metadata 权限、rootless Podman、无容器主机 absent 行为。 |
| Phase 12 | `go test ./internal/archive`、`go test ./...`、Phase 12 CLI、`tar tzf`、archive summary JSON/hash 校验、`--archive` flag smoke、`make linux` | Halley PASS | Plato FAIL -> PASS | Parfit PASS -> PASS | Linux 下确认真实大采集输出归档耗时/权限、低权限写归档目录、跨文件系统输出路径、scanner artifact 加入后的整包复验。 |
| Phase 13 | `go test ./internal/scanners`、`go test ./...`、Phase 13 scan none CLI、tmbrfix mac unsupported CLI、yara absent CLI、archive-with-scanner、`make linux` | Russell FAIL -> PASS | Zeno FAIL -> PASS | Herschel PASS -> PASS | Linux 下确认 tmbrfix 32-bit i386 payload smoke、amd64 32-bit compatibility、真实 YARA/osquery、权限/超时、clean confirm/force 语义。 |
| Phase 14 | `go test ./...`、`make clean && make linux`、quick/standard/deep/minimal-safe/scanner profile smoke、JSONL parse、manifest check、deep archive hash/tar check、README/operator guide、Linux VM checklist | McClintock FAIL -> PASS | Singer PASS -> PASS | Laplace PASS | Linux 下补全部真实 runtime smoke：amd64/arm64/386、root 权限、真实 `/proc`/`/sys`、容器、scanner、发行版差异。 |

## mac 侧不可完成的验证

以下项目在 macOS arm64 开发机无法完整证明，必须等用户提供 Linux VM 后补测：

- `/proc`、`/sys` 正常存在时的 Linux 成功采集路径。
- root 权限下 `/etc/sudoers`、systemd、journal、audit、container runtime 等敏感面。
- Linux amd64/arm64/386 二进制真实运行 smoke，而不仅是交叉编译产物检查。
- tmbrfix 32-bit x86 scanner compatibility。
- 容器、iptables/nftables、NetworkManager/systemd-networkd、auditd 等 Linux-only 环境差异。

## Linux VM 测试基线

当前测试主机：

- UTM VM：`linux-dfir-ubuntu-arm64`
- 系统：Ubuntu 24.04.4 LTS ARM64
- SSH：`dfir@192.168.64.2`
- Go：`go1.26.3 linux/arm64`
- 状态：已完成基础依赖、Go 环境、SSH key、`go test ./...`、`standard` profile smoke 和归档验证。

UTM GUI 没有常规“快照管理器”，`utmctl` 也没有 `snapshot` 子命令。本项目采用“关机后复制 `.utm` bundle”的离线基线快照方式。

当前基线快照：

```text
/Users/nel/projects/vm_images/utm_snapshots/linux-dfir-baseline-ubuntu2404-arm64-go126.utm
```

最新基线路径记录：

```text
/Users/nel/projects/vm_images/utm_snapshots/latest-baseline-path.txt
```

约定：

- 创建基线前必须先优雅关机，确认 `/opt/homebrew/bin/utmctl status linux-dfir-ubuntu-arm64` 为 `stopped`。
- 复制源为 `/Users/nel/Library/Containers/com.utmapp.UTM/Data/Documents/linux-dfir-ubuntu-arm64.utm/`。
- 使用 `rsync -a --progress <source>/ <baseline>/` 复制整个 bundle。
- 恢复时先停止 UTM/VM，再用基线 bundle 替换 active bundle；不要复制运行中的 VM。

## 当前下一步

AI JSONL 内容质量加固：

- 当前状态：Done；按“只采事实、不做分析、单一 `ai/evidence.jsonl`、只增不减”原则，完成对 VM 实采 JSONL 的逐行内容质量修复与回归。
- 已修复：`scanner_runs` disabled/absent 记录不再输出 `0001-01-01T00:00:00Z`；`persistence_file` 缺失文件不再输出零时间；systemd enabled symlink 与 unit 文件 `entity_id` 去重；日志 raw copy/absent/status 行增加 `record_subtype=status` 便于 AI agent 过滤；firewall 命令存在但无规则时输出 `facts/firewall_rules` 的 `rule_type=status`、`expression=no_rules`；文件枚举中历史/current collector artifact 目录按明确 marker 过滤，避免旧 ATTK/Go 运行目录污染 `entities/file`/`facts/file_hashes`/`facts/file_flags`。
- 输出边界：仍只保留事实字段，不新增 `risk`、`severity`、`verdict`、`suspicious`、`malicious` 等工具侧分析字段；外部 scanner/YARA 规则名中的字符串不视为工具侧分析字段。
- 本地验证：`go test ./internal/collectors/files ./internal/collectors/persistence ./internal/collectors/logs ./internal/collectors/network ./internal/scanners -count=1`、`go test ./...`、`GOOS=linux GOARCH=arm64 go build -o /tmp/dfir-collector-quality-arm64 ./cmd/dfir-collector` 均通过；精确 JSON 字段扫描无命中。
- VM 验证：Ubuntu ARM64 VM root `deep --scan none` 生成 `ai/evidence.jsonl` 186520 行、46 个 stream；`invalid_json=0`、`duplicate_entity_ids=0`、`zero_time_hits=0`、`analysis_fields=0`；`facts/firewall_rules=3` 且均为 `no_rules` status；scanner disabled 记录无 started/completed 零时间。
- VM 备注：最终剩余 `/tmp/dfir-quality/dfir-collector` 命中来自 process 采集中的当前采集器进程；`/tmp/attk-original-run/attk_log` 命中来自历史 auth/sudo 日志命令行。二者属于系统事实，不在文件枚举层过滤。
- 独立 gate：Faraday review PASS；Copernicus test PASS。
- 产物路径：VM `/tmp/dfir-quality/out/ai/evidence.jsonl`；Mac 抽样副本 `/tmp/dfir-quality-review-final3/evidence.jsonl`。

P0 Persistence / Network AI-native enhancement：

- 当前状态：Done；按用户要求完成 Dev / review / test 独立门禁，并完成 Ubuntu ARM64 VM `deep --scan none` 实采验证。
- 已实现：systemd directive/drop-in/enabled symlink、shell profile/export/source/alias/exec-like、loader persistence、SSH authorized_keys options、sshd_config keyword/values、sudoers subject/runas/tags/commands、interface IPv4/MAC/MTU/flags、hosts/resolv、socket owner enrichment、network flows、conntrack、nft/iptables、proxy/tunnel config。
- AI 输出安全边界：新增共享 `internal/redact`；AI 结构化字段脱敏 token/password/private key/API key/PSK、URL credential/query secret、quoted secret、process/network owner cmdline、auth/audit log message/command/fields、private-key marker。`legacy/` 与 `ai/raw/` 保留原文复核。
- 独立 gate：Persistence Dev PASS；Network Dev 变更由 main 集成；Hume review 多轮 blocking 已关闭并 PASS；Pauli test 多轮强制重跑 PASS。
- 本地验证：`go test ./internal/redact ./internal/collectors/process ./internal/collectors/logs ./internal/netproc ./internal/collectors/persistence ./internal/collectors/network -count=1`、`go test ./...`、Linux ARM64 交叉编译均通过。
- VM 验证：最终 evidence `invalid_json=0`、`line_count=184785`；`entities/systemd_unit=1446`、`facts/persistence_items=1094`、`facts/network_persistence=2`、`entities/process=128`、`facts/auth_events=3037`、`facts/network_flows=138`、`entities/interface=2`、`facts/dns_config=8`、`facts/conntrack_entries=2`。
- VM 敏感词检查：`vm2-super-secret`、`vm-super-secret`、`tskey-vm2`、`tskey-vm`、`correct horse`、`user:pass`、`BEGIN OPENSSH PRIVATE KEY`、`END OPENSSH PRIVATE KEY`、`Test$$1234` 在最终 `ai/evidence.jsonl` 中均无命中。
- 产物路径：VM `/tmp/dfir-pn/out/ai/evidence.jsonl`；Mac 抽样副本 `/tmp/dfir-pn-review-final/evidence.jsonl`。

AI-native logs hardening：

- 当前状态：Done；已补齐 AI 版 `evidence.jsonl` 中登录/认证关键结构化事实，不再只依赖 raw copy。
- 已实现：`wtmp/btmp` 384/400 字节 Linux utmp 自适应解析、`lastlog` 292/296 字节解析、`facts/login_events`、classic syslog + ISO8601/RFC3339 syslog 解析、sudo command/session 的 `actor_user`/`target_user`/`session_action` 事实字段、audit key/value 分隔符加固。
- VM 验证：Ubuntu ARM64 VM root `deep --scan none` 生成 `facts/login_events=36`、`facts/auth_events=2748`、`facts/log_events=10427`、`facts/audit_events=6883`；`login_success/login_failed/last_login/system_boot/runlevel/logout` 等事件均进入单一 `ai/evidence.jsonl`；登录认证事件 timestamp 缺失数为 0，IPv4 地址误读样本数为 0。
- 产物路径：VM `/tmp/dfir-ai-login/out/ai/evidence.jsonl`；Mac 抽样副本 `/tmp/dfir-ai-login-review/evidence-final-fixed.jsonl`。
- 后续扩展路线见 `AI_NATIVE_EXPANSION_PLAN_CN.md`。

Deep 输出合同优化：

- 当前状态：Done；standard gate 已完成并通过双 subagent 复核，deep container/scanner 已完成本地重构、Linux VM smoke、独立 review/test gate。
- 目标范围：`deep` profile 中 container/scanner 不再写 `parsed/*`，scanner 不再写 `severity`，所有结构化输出继续合并到单一 `ai/evidence.jsonl`。
- 已完成：`ATTK_PARITY_DEEP_CONTAINER_SCANNER_CN.md`、container stream 收敛、scanner stream 收敛、本地 `go test ./...`、Ubuntu ARM64 VM root `deep --scan none` smoke、Huygens review PASS、Lovelace test PASS。

Phase 14 End-to-End：

- 当前状态：Done；mac 侧主验收、文档和最终 subagent gate 已完成。
- 目标范围：形成可交付的一次性应急采集包；Linux amd64/arm64/386 构建、quick/standard/deep/minimal-safe smoke、JSON/JSONL parse、manifest/archive 校验、operator guide。
- 已完成：`README.md` operator guide、`PHASE14_E2E_CHECKLIST_CN.md`、`ATTK_ORIGINAL_GO_COMPARE_VM_20260604_CN.md`、mac 上 quick/standard/deep/minimal-safe/scanner profile smoke、deep archive、JSONL parse、manifest count、Linux amd64/arm64/386 交叉构建、Ubuntu ARM64 VM 原版 ATTK vs Go deep 非扫描采集对比。
- 原版对比结果：原版非扫描采集文件 366 个，Go legacy 非扫描采集文件 1421 个，Go AI stream 41 个；补齐 `legacy/system/kernel/modprobe_-n-l-v.out` 和 per-module `modinfo` legacy 后，`missing_or_partial=0`。
- mac 上可完成构建、profile smoke、JSON/JSONL、archive、manifest、scanner skip；Linux VM 后补真实 `/proc`/`/sys`、root 权限、真实容器、真实 scanner、runtime smoke。
- Linux VM 后继续按补测清单执行真实 runtime smoke。

Phase 13 收尾记录：

- 已实现范围：`internal/scanners` 框架、scanner disabled records、tmbrfix payload SHA256/MD5/size/type、Linux/i386 compatibility skip、clean args gating、YARA 标准输出解析、stdout/stderr raw/legacy 输出、scanner runs/findings JSONL、archive-with-scanner。
- 当前输出：scanner 结构化记录统一进入 `facts/scanner_runs` 和 `facts/scanner_findings`，不写 `severity`、`verdict` 或风险判断字段；stdout/stderr 原文仍在 `ai/raw/scanners/` 和 `legacy/filescan/`。
- 已验收：包测、全量测试、Phase 13 scan none/tmbrfix/yara CLI、mac tmbrfix unsupported、archive-with-scanner、Linux amd64/arm64/386 交叉构建；修复 Linux/amd64 测试可移植性和 YARA 标准输出漏报。
- Linux VM 后补 tmbrfix 32-bit i386 payload smoke、amd64 32-bit compatibility、真实 YARA/osquery、权限/超时、clean confirm/force 语义。

Phase 12 收尾记录：

- 已实现范围：`internal/archive` tar.gz 归档、路径安全校验、symlink 不跟随外部、整包 SHA256/MD5/size、`ai/archive_summary.json` 外部报告、`phase12-archive` 自动归档、`--archive` 显式归档。
- 已验收：包测、全量测试、Phase 12 CLI、tar entry 安全检查、summary hash/manifest artifact_count 复算、Linux amd64/arm64/386 交叉构建；修复 archive parent symlink 指回 source 的 containment 问题。
- Linux VM 后补真实大采集输出、权限失败、跨文件系统输出路径、scanner artifact 加入后的整包复验。

Phase 11 收尾记录：

- 已实现范围：Docker/containerd/Podman/Kubernetes/CRI-O cgroup hint、`/proc/[pid]/status/cmdline/cgroup/mountinfo/ns` 关联、runtime metadata raw copy + artifact metadata、legacy container 输出、AI entity/fact 输出。
- 输出说明：所有结构化记录统一进入 `ai/evidence.jsonl`，用 `stream=entities/container`、`stream=facts/process_containers`、`stream=facts/namespaces`、`stream=facts/cgroups`、`stream=artifacts/runtime_metadata` 区分内容；旧的 container alias stream 已合并，避免重复记录。
- 已验收：包测、全量测试、Phase 11 CLI、JSONL parse、Linux amd64/arm64/386 交叉构建；修复 mac/no-`/proc` 先读 runtime metadata 和 Kubernetes pod UID systemd escape 规范化问题。
- Linux VM 后补真实容器 runtime、cgroup v1/v2、namespace 关联、rootless Podman、权限失败路径。

## 跨 Phase 加固事项

- `common.TimelineFileStat` 当前吞掉 timeline 写入失败；后续输出框架加固时改成返回 error，并由各 collector 决定是否阻断。
- Persistence 的 `scanSystemd()` 会重复读取 `/etc/passwd`，后续可改为复用 `Collect()` 开头的 users。
- Persistence 的 systemd `EnabledHint` 是 unit 文件 hint，不等价于真实 enabled symlink 状态；Linux VM 验证后可增强 symlink 语义。
- File Enum legacy `file_hashes.out` 会二次 hash，后续可复用 AI hash 结果生成 legacy，避免 race 不一致。
- File Enum `WalkDir` 二次 `Lstat` race 当前静默跳过，后续可按需记录到 `ai/evidence.jsonl` 的 `record_type=error_event`。
- Package 的 rpm 实现依赖 `rpm` native command fallback；Linux VM 后确认 `rpm -q --filesbypkg -a` 在目标发行版上的输出变体。
- Package 的 dpkg status parser 放大了 scanner buffer，但未显式输出 `scanner.Err()`；极端超长字段可在后续加错误事件。
- Browser raw legacy copy 当前路径为 `legacy/browser/raw/browser/...`，后续可简化为 `legacy/browser/raw/...`。
- Browser locked/permission-denied DB 目前主要靠 damaged DB 和 errors 行为覆盖，Linux VM 后补真实 active browser/其他用户权限场景。
- Logs syslog 年份按当前年份推断，已在记录中标记 `time_inferred`；Linux VM/真实历史日志可进一步按文件 mtime 估算跨年 rotated logs。
- Logs audit rules 仅存在时复制，完全不存在时不单独写 audit_rules absent；如后续需要合规审计视角可补专用 records。
- Timeout 当前是 cooperative run-level context；多数 Go-native collector 会检查或传递 context，但少数路径和 native fallback（例如 rpm）仍可进一步改为 `CommandContext` 或更密集检查，以避免极端 hang。
