# Linux DFIR Collector 模块化实现路线图

生成时间：2026-06-02

## 0. 执行原则

本路线图用于指导 Go 版 Linux DFIR 一次性采集工具的模块化实现。每个 phase 必须同时满足：

1. 模块功能完成。
2. `legacy/` 输出可用于人工复核，并尽量贴近原始 ATTK 输出习惯。
3. `ai/evidence.jsonl` 是 AI agent 的单一主证据入口；每行用 `record_type`、`stream`、`collector` 区分内容。
4. 采集能力只增不减；若替换实现来源，必须保持原有证据面或明确标记旧路径为 compatibility-only。
5. AI 结构化输出只落一个 JSONL 文件；新增模块不得再创建模块级 `ai/parsed/*.jsonl`、`ai/errors.jsonl`、`ai/timeline.jsonl` 等分文件。
6. 工具只做采集，不做分析判断；输出事实、来源、采集状态，不输出风险标签、严重性、verdict 或分析结论。
7. 多个采集位置观察到同一实体或事实时，按稳定 identity 合并字段并输出并集，避免重复 partial records。
8. 单元测试、集成测试、构建测试通过。
9. 每个 phase 完成后必须启动独立 subagent 做 review 和测试。

当前生效 stream 合同：

```text
host_profile
system_resource
entities/host
entities/user
entities/group
entities/process
entities/socket
entities/interface
entities/persistence_file
entities/systemd_unit
entities/kernel_module
entities/package
entities/file
entities/browser_profile
entities/container
facts/mounts
facts/mountinfo
facts/time
facts/routes
facts/arp
facts/cron_entries
facts/persistence_items
facts/file_package_owners
facts/log_events
facts/auth_events
facts/audit_events
facts/file_hashes
facts/suid_files
facts/open_files
facts/recent_files
facts/file_flags
facts/browser_history
facts/browser_downloads
facts/browser_cookies
facts/browser_bookmarks
facts/process_containers
facts/namespaces
facts/cgroups
facts/scanner_runs
facts/scanner_findings
artifacts/runtime_metadata
errors
timeline
collection_log
```

历史 phase 示例中若仍出现 `parsed/*`，只用于说明旧迁移目标，实际实现与验收必须以上表、`README.md`、`ATTK_PARITY_QUICK_PERSISTENCE_CN.md`、`ATTK_PARITY_STANDARD_CORE_CN.md`、`ATTK_PARITY_DEEP_CONTAINER_SCANNER_CN.md` 为准。

默认输出：

```text
attk_log/<session>/
  legacy/
  ai/
```

默认构建目标：

```text
darwin/arm64       本机开发验证
linux/amd64        主目标
linux/arm64        次目标
linux/386          兼容原始 tmbrfix 场景
```

基础 schema 与证据字段要求：

```text
schemas/
  manifest.schema.json
  collection_log.schema.json
  errors.schema.json
  artifact_index.schema.json
  timeline_event.schema.json
  entity.schema.json
```

所有 AI JSON/JSONL 记录至少应能追溯：

```text
case_id
host_id
session_id
collector
artifact_id
source_path
source_type          procfs|sysfs|file|native_command|generated|scanner
source_trust         high|medium|low
collected_at
raw_artifact_ref
```

phase 验收应优先使用 phase-specific profile，避免尚未实现的 collector 被误拉入验收：

```text
profiles/phase1.yaml
profiles/phase2.yaml
profiles/phase3-kernel.yaml
profiles/phase4-process.yaml
...
```

未实现 collector 的默认行为必须明确：开发阶段验收 profile 不应包含未实现 collector；正式 profile 若包含未实现 collector，必须记录 `collector_skipped` 事件，不能静默跳过。

## 1. Subagent Gate 要求

每个 phase 必须使用 subagent 做开发辅助、独立 review 和独立测试。主 agent 负责调度、集成、修复和最终验收：

| Subagent | 角色 | 任务 |
|---|---|---|
| Dev subagent | 独立开发辅助 | 在 fork workspace 中实现或提出 patch/方案，输出改动范围、测试建议和风险；主 agent 负责集成 |
| Review subagent | 独立代码审查 | 审查 diff、采集逻辑、副作用、证据可信度、路径安全、schema 一致性 |
| Test subagent | 独立测试验证 | 在 forked workspace 中运行测试、构建、CLI 验收命令，检查输出结构 |

建议流程：

```text
Subagent A: dev，独立实现或给 patch 方案。
Main agent: 集成实现并跑本地验收。
Subagent B: review only，不改代码，输出 findings。
Subagent C: test only，运行验收命令，输出 pass/fail 和日志摘要。
```

主 agent 不得在 review/test 两个 subagent 都给出结论前声明 phase 完成。

如果 subagent 发现问题：

1. 主 agent 修复。
2. 重新运行本地测试。
3. 如果修复触及本 phase 的采集逻辑、schema、输出路径、权限处理或验收命令，必须重新启动对应 review/test subagent 复验。

每个 phase 的最终完成条件：

```text
local tests pass
+ review subagent no blocking findings
+ non-blocking findings recorded as residual risk or fixed
+ test subagent acceptance pass
+ final summary includes changed files and verification
```

## 2. Phase 0：工程环境与骨架

状态：已完成。

### 范围

- Go module 初始化。
- CLI 参数骨架。
- profile 配置。
- 双轨输出目录初始化。
- Makefile。
- 本机与 Linux 交叉编译验证。

### 已有文件

```text
go.mod
go.sum
Makefile
README.md
cmd/dfir-collector/main.go
internal/app/app.go
internal/profile/profile.go
profiles/*.yaml
```

### 验收标准

- `go test ./...` 通过。
- `make build` 通过。
- `make linux` 通过。
- 运行 CLI 后生成：

```text
legacy/
ai/
ai/raw/
ai/evidence.jsonl
ai/manifest.json
ai/artifact_index.json
```

## 3. Phase 1：输出框架、Manifest 与 Collection Log

### 目标

建立所有后续模块共用的证据输出框架。

### 实现模块

```text
internal/evidence/
internal/output/
internal/session/
internal/artifact/
internal/timeline/
internal/integrity/
```

### 功能范围

- session id 生成。
- host/case metadata 占位。
- `manifest.json` 写入。
- collection event 写入 `ai/evidence.jsonl`。
- artifact id 生成。
- artifact hash/integrity primitives。
- timeline event 写入 `ai/evidence.jsonl`。
- legacy 文件写入 helper。
- AI evidence JSONL 写入 helper。
- error/event 统一写入 `ai/evidence.jsonl`。
- `schemas/` 与 golden JSONL fixture。

### legacy 输出

```text
legacy/command_not_found.out
legacy/SUMMARY        可先写占位或由 Phase 2 补齐
```

### ai 输出

```text
ai/evidence.jsonl
ai/manifest.json
ai/artifact_index.json
ai/raw/
```

控制文件索引规则：

- `ai/manifest.json` 是证据链根控制文件，不做自索引。
- `ai/artifact_index.json` 由 manifest 索引，但不做自索引。
- `ai/evidence.jsonl` 是 AI 主消费文件，汇聚 host/profile、parsed records、collection log、timeline、errors 等结构化记录。
- `ai/evidence.jsonl` 的每一行必须包含 `record_type`、`stream`、`collector`、source metadata 和 `data`。
- `artifact_index.json` 索引所有非控制证据文件，例如 legacy 输出、`ai/evidence.jsonl`、`ai/raw/` 原始拷贝。
- 成功路径下不创建单独的 error 文件；无错误即 `evidence.jsonl` 中没有 `record_type=error_event`。
- 如后续需要完整归档级完整性，由 Phase 12 archive summary 对整包 hash 兜底。

### 单元测试

- session id 格式。
- JSONL writer 每条一行且合法 JSON。
- manifest artifact hash 计算。
- timeline event required fields 验证。
- artifact index required fields 验证。
- legacy 路径不能逃逸输出目录。
- 输出目录内部 symlink 必须拒绝，不能跟随写出输出根。
- 重复 artifact id 处理。

### 集成测试

运行：

```sh
go test ./...
go run ./cmd/dfir-collector --profile phase1 --output /tmp/dfir-phase1 --output-mode dual
jq -e '.session_id and .created_at and .artifacts' /tmp/dfir-phase1/ai/manifest.json
test -s /tmp/dfir-phase1/ai/evidence.jsonl
jq -e 'select(.record_type=="collection_event" and .data.event=="session_start")' /tmp/dfir-phase1/ai/evidence.jsonl >/dev/null
test -s /tmp/dfir-phase1/ai/artifact_index.json
```

检查：

- `ai/manifest.json` 存在且 JSON 合法。
- `ai/evidence.jsonl` 存在，且所有行均可逐行 JSON 解析；AI agent 默认只需读取该文件。
- `ai/evidence.jsonl` 中 `record_type=collection_event` 至少包含 session start/end。
- `ai/artifact_index.json` 中每个 artifact 有 hash、collector、source_type。
- 成功路径不要求错误分文件存在；无错误即 `ai/evidence.jsonl` 中没有 `record_type=error_event`。
- 预置 `legacy -> /tmp/outside` 这类 symlink 时 collector 必须失败，且不能写出 output root。
- `legacy/` 和 `ai/` 目录均存在。

### Review 标准

- 输出路径必须经过 join/clean，并禁止 `../` 逃逸。
- JSON schema 字段稳定。
- 错误记录不吞异常。
- 不产生系统修改行为。

### 验收标准

- 所有测试通过。
- phase 输出可被 `jq` 或 Go JSON parser 解析。
- subagent review 无 P0/P1 问题。
- subagent test 验收通过。

## 4. Phase 2：Host/System/User/Disk/Time 基础采集

### 目标

复刻 ATTK 的系统基础采集面，并生成结构化 host profile。

### 实现模块

```text
internal/collectors/host/
internal/collectors/system/
internal/collectors/users/
internal/collectors/disk/
internal/collectors/time/
```

### 功能范围

- `/etc/os-release`
- `/proc/meminfo`
- `/proc/cpuinfo`
- `uname`
- `/etc/passwd`
- `/etc/group`
- `/etc/sudoers`
- `/proc/mounts`
- `/proc/self/mountinfo`
- `/etc/localtime` metadata
- SSH host key stat metadata

### legacy 输出

尽量贴近 ATTK：

```text
legacy/SUMMARY
legacy/system/uname_-a.out
legacy/system/vmstat_-s.out              native command: vmstat -s, if present
legacy/system/proc_meminfo.out           direct source: /proc/meminfo
legacy/system/user/passwd
legacy/system/user/group
legacy/system/user/sudoers
legacy/system/disks/mounts.out
legacy/system/time/localtime.json        Go 版新增，可接受
```

### ai 输出

```text
ai/evidence.jsonl stream=host_profile
ai/evidence.jsonl stream=entities/user
ai/evidence.jsonl stream=entities/group
ai/evidence.jsonl stream=facts/mounts
ai/evidence.jsonl stream=facts/mountinfo
ai/evidence.jsonl record_type=timeline_event        基础文件 metadata 事件
```

### 单元测试

- `/etc/os-release` parser。
- passwd/group parser。
- proc meminfo parser。
- mountinfo parser。
- sudoers 复制失败时错误记录。

### 集成测试

运行：

```sh
go test ./...
go run ./cmd/dfir-collector --profile phase2 --output /tmp/dfir-phase2
jq -e 'select(.stream=="host_profile" and .data.os and .data.kernel and .data.arch and .data.hostname)' /tmp/dfir-phase2/ai/evidence.jsonl >/dev/null
jq -e 'select(.stream=="entities/user")' /tmp/dfir-phase2/ai/evidence.jsonl >/dev/null
```

检查：

- `legacy/SUMMARY` 存在。
- `ai/evidence.jsonl` 中 `stream=host_profile` 的 `data` 字段包含 OS、kernel、arch、hostname。
- users/groups 记录进入 `ai/evidence.jsonl`，且 envelope 每行 JSON 合法。

### Review 标准

- 敏感文件只复制，不解析密码 hash。
- 权限不足应记录错误，不终止整个采集。
- 不依赖目标机 `cat/awk/grep`。
- legacy 输出和 ai 输出来源能互相追溯。

### 验收标准

- Linux 环境下能完成基础采集。
- macOS 开发环境运行时允许有限 fallback，但 Linux 目标测试必须通过。
- non-root smoke test 不崩溃，权限不足写入 `ai/evidence.jsonl` 的 `record_type=error_event`。
- root Linux test 能采集 sudoers、mount、SSH host key metadata 等敏感面。
- subagent review 无 blocking findings，test subagent 验收通过。

## 5. Phase 3：Kernel 内核与模块采集

### 目标

补齐 ATTK `KernelInfo`，并为后续文件枚举提供内核模块文件线索。

### 实现模块

```text
internal/collectors/kernel/
```

### 功能范围

- `/proc/modules`。
- `/sys/module/*` metadata。
- module name、size、refcount、dependencies。
- module file path 推断。
- `modinfo` native fallback 作为后续增强项；本 phase 不强制执行外部命令。
- 内核版本、boot command line、taint 信息。

### legacy 输出

```text
legacy/system/kernel/modules.out
legacy/system/kernel/cmdline
legacy/system/kernel/tainted
```

### ai 输出

```text
ai/evidence.jsonl stream=entities/kernel_module
ai/evidence.jsonl record_type=timeline_event
```

### 单元测试

- `/proc/modules` parser。
- `/sys/module` metadata parser。
- module file path 去重。
- `/proc`/`/sys` 缺失时写 absent structured record。

### 集成测试

```sh
go test ./...
go run ./cmd/dfir-collector --profile phase3-kernel --output /tmp/dfir-phase3-kernel
jq -e 'select(.stream=="entities/kernel_module" and .collector=="kernel" and (.data|has("exists")))' /tmp/dfir-phase3-kernel/ai/evidence.jsonl >/dev/null
jq -e 'select(.record_type=="error_event" and .collector=="kernel")' /tmp/dfir-phase3-kernel/ai/evidence.jsonl >/dev/null || true
```

Linux VM/root 补测时追加：

```sh
test -s /tmp/dfir-phase3-kernel/legacy/system/kernel/modules.out
test -s /tmp/dfir-phase3-kernel/legacy/system/kernel/cmdline
test -s /tmp/dfir-phase3-kernel/legacy/system/kernel/tainted
jq -e 'select(.stream=="entities/kernel_module" and .collector=="kernel" and .data.exists==true and .data.name!="")' /tmp/dfir-phase3-kernel/ai/evidence.jsonl >/dev/null
```

### Review 标准

- 不依赖 `lsmod` 作为主采集。
- `/sys/module` 缺失或权限不足时不中断。
- 本 phase 不强制执行 `modinfo`；后续若启用 native fallback，必须记录命令路径、参数、exit code、source trust。
- module file path 只作为线索，不假定一定存在。

### 验收标准

- 覆盖原版 ATTK KernelInfo 外层采集面。
- kernel module entities 可被 File Enum phase 复用。
- subagent review 无 blocking findings，test subagent 验收通过。

## 6. Phase 4：Process 进程采集

### 目标

用 Go 直接读取 `/proc`，替代原版对 `ps/lsof` 的强依赖。

### 实现模块

```text
internal/collectors/process/
internal/procfs/
```

### 功能范围

- 枚举 `/proc/[pid]`。
- 读取：
  - `status`
  - `cmdline`
  - `environ` 摘要或脱敏版
  - `exe` symlink
  - `cwd` symlink
  - `root` symlink
  - `maps` 摘要
  - `fd` 列表
- 记录进程消失、权限不足。

### legacy 输出

```text
legacy/process/ps_auxw.out       native command: ps auxw, if present
legacy/process/ps_-elf.out       native command: ps -elf, if present
legacy/process/lsof.out          native command: lsof, if present
legacy/process/jobs_-l.out       generated note: Go collector has no shell job table
legacy/process/procfs_ps_auxw.out
legacy/process/procfs_ps_-elf.out
legacy/process/procfs_lsof.out
```

### ai 输出

```text
ai/evidence.jsonl stream=entities/process
```

### 单元测试

- proc status parser。
- cmdline null-byte parser。
- environ 脱敏。
- fd symlink 分类。
- 进程消失错误处理。

### 集成测试

运行：

```sh
go test ./...
go run ./cmd/dfir-collector --profile phase4-process --output /tmp/dfir-phase4-process
jq -e 'select(.stream=="entities/process" and .data.pid and .data.ppid and .data.cmdline)' /tmp/dfir-phase4-process/ai/evidence.jsonl >/dev/null
test -s /tmp/dfir-phase4-process/legacy/process/procfs_ps_auxw.out
```

检查：

- 当前 collector 自身进程出现在 `processes.jsonl`。
- `legacy/process/procfs_ps_auxw.out` 非空。
- fd 采集不会因权限不足导致整体失败。

### Review 标准

- 不执行 `ps` 作为主采集。
- 不完整读取超大 `maps` 或无限制写入。
- environ 默认脱敏或摘要化。
- PID race condition 处理合理。

### 验收标准

- 可在 Linux amd64 测试机上完成进程采集。
- JSONL 合法且含 PID、PPID、UID、cmdline、exe。
- non-root smoke test 不崩溃；受限 `/proc/*/environ`、`fd` 记录 permission error。
- subagent review 无 blocking findings，test subagent 验收通过。

## 7. Phase 5：Network 网络采集

### 目标

用 `/proc/net` 和进程 fd socket inode 关联，生成结构化网络连接视图。

### 实现模块

```text
internal/collectors/network/
internal/netproc/
```

### 功能范围

当前验收范围：

- `/proc/net/tcp`
- `/proc/net/tcp6`
- `/proc/net/udp`
- `/proc/net/udp6`
- `/proc/net/unix`
- `/proc/net/route`
- `/proc/net/arp`
- `/proc/net/dev` 与 `/proc/net/if_inet6`。
- `/etc/hosts`
- `/etc/resolv.conf`
- DHCP leases。
- socket inode -> PID/process 关联。
- native compatibility snapshots：`ifconfig`、`route`、`netstat`、`arp`、`ip addr/route/link/rule`，来源标记为 `native_command`。

后续 hardening，不作为当前 phase 完成门槛：

- `/proc/net/ipv6_route`。
- netlink 原生 interface addr/link/rule。
- NetworkManager、systemd-networkd、systemd-resolved 配置和状态文件。
- iptables/nftables ruleset，native fallback 标记为 `native_command`。

### legacy 输出

```text
legacy/network/ifconfig_-a.out       native command, if present
legacy/network/route_-nv.out         native command, if present
legacy/network/netstat_-avpeW.out    native command, if present
legacy/network/netstat_-rn.out       native command, if present
legacy/network/netstat_-s.out        native command, if present
legacy/network/arp_-a.out            native command, if present
legacy/network/ip_addr.out           native command, if present
legacy/network/ip_route.out          native command, if present
legacy/network/ip_link.out           native command, if present
legacy/network/ip_rule.out           native command, if present
legacy/network/proc_net_sockets.out
legacy/network/proc_net_route.out
legacy/network/proc_net_arp.out
legacy/network/proc_net_interfaces.out
legacy/network/hosts
legacy/network/resolv.conf
```

### ai 输出

```text
ai/evidence.jsonl stream=entities/socket
ai/evidence.jsonl stream=facts/routes
ai/evidence.jsonl stream=facts/arp
ai/evidence.jsonl stream=entities/interface
ai/raw/network_config/...
```

### 单元测试

- IPv4/IPv6 hex address parser。
- TCP state parser。
- route parser。
- interface address parser。
- DHCP lease parser。
- socket inode association。

### 集成测试

- 启动本地测试 TCP listener。
- 运行 collector。
- 验证 listener 合并在 `ai/evidence.jsonl` 的 `stream=entities/socket`，并带 `is_listener=true`。
- fixture 验证 DHCP 配置复制和结构化摘要。
- NetworkManager/resolved 与 iptables/nftables 作为后续 hardening 验收项。

### Review 标准

- 不依赖 `netstat` 作为主采集。
- 地址、端口、状态转换准确。
- 关联不到 PID 时不能丢弃连接。
- IPv6 不应跳过。
- 当前防火墙未采集时不写 facts record，避免把未实现状态伪装成目标主机事实；后续补齐 ruleset 时 native command fallback 必须记录命令来源和失败原因。

### 验收标准

- 可输出监听端口、已建立连接、路由、ARP。
- 可输出接口、DNS、DHCP 证据。
- NetworkManager/networkd/resolved 与 iptables/nftables 证据属于后续 hardening，不阻塞当前 phase。
- 与 native `ss/netstat` 可人工抽样对照。
- subagent review 无 blocking findings，test subagent 验收通过。

## 8. Phase 6：Persistence 持久化采集

### 目标

覆盖原版 cron/rc/init，并补齐现代 Linux 常见持久化点。

### 实现模块

```text
internal/collectors/persistence/
```

### 功能范围

- `/etc/cron*`
- `/var/spool/cron*`
- at jobs。
- `/etc/rc*`
- `/etc/init`
- `/etc/init.d`
- systemd system/user units and timers，包括 `/etc/systemd/system`、`/usr/lib/systemd/system`、`/lib/systemd/system`、`/run/systemd/system`、用户级 unit 目录。
- `/etc/profile`
- `/etc/profile.d`
- XDG autostart。
- 用户 home 下 shell rc/profile
- `authorized_keys`
- `sshd_config`
- `/etc/sudoers.d`
- `/etc/ld.so.preload`
- PAM 配置目录

### legacy 输出

```text
legacy/autorun/etc/
legacy/autorun/var/spool/
legacy/autorun/systemd/
legacy/autorun/ssh/
```

### ai 输出

```text
ai/evidence.jsonl stream=entities/persistence_file
ai/evidence.jsonl stream=entities/systemd_unit
ai/evidence.jsonl stream=facts/cron_entries
ai/evidence.jsonl stream=facts/persistence_items
ai/evidence.jsonl record_type=timeline_event
```

### 单元测试

- cron parser。
- systemd unit metadata parser。
- authorized_keys parser。
- shell profile path discovery。

### 集成测试

- 使用 testdata 模拟 cron/systemd/ssh 文件树。
- collector 支持 `--root` 或 test hook 指向 fixture。

### Review 标准

- 不跟随危险 symlink 逃逸采集根。
- home 遍历有限制。
- private key 不应默认采集内容，只采 metadata/hash。
- shell history 与 authorized_keys 标记敏感。

### 验收标准

- 原版 ATTK autorun 覆盖面全部保留。
- systemd、ssh、profile 持久化点有结构化输出。
- sudoers.d、at jobs、XDG autostart 有结构化输出或明确 unsupported/absent 记录。
- subagent review 无 blocking findings，test subagent 验收通过。

## 9. Phase 7：File Enum 文件枚举与哈希

### 目标

复刻 ATTK `EnumInfo` 的文件发现、文件信息和 hash 能力，并记录文件事实观察。本 phase 不包含 package ownership，包归属放到 Phase 8。

### 实现模块

```text
internal/collectors/files/
internal/hash/
internal/filetype/
```

### 功能范围

- 内核模块文件。
- 进程 exe/cwd/fd 指向文件。
- persistence 目标文件。
- browser plugin。
- SUID/SGID。
- world-writable。
- `/tmp`、`/var/tmp`、`/dev/shm`。
- 常见 webroot 可配置。
- 最近修改文件。
- SHA256、SHA1、MD5。
- 文件类型识别。

### legacy 输出

```text
legacy/enum/enum_file.out
legacy/enum/file_info.out
```

### ai 输出

```text
ai/evidence.jsonl stream=entities/file
ai/evidence.jsonl stream=facts/suid_files
ai/evidence.jsonl stream=facts/open_files
ai/evidence.jsonl stream=facts/recent_files
ai/evidence.jsonl stream=facts/file_hashes
ai/evidence.jsonl stream=facts/file_flags
ai/evidence.jsonl record_type=timeline_event
```

### 单元测试

- hash 计算。
- 文件大小上限。
- symlink 策略。
- file category 分类。
- enum_file 去重。

### 集成测试

- fixture 文件树包含 SUID、world-writable、recent file、symlink。
- 验证枚举和 hash 输出。

### Review 标准

- 不无限递归。
- 不读取超过配置上限的大文件。
- 不跟随 symlink 到敏感逃逸路径。
- hash 失败需记录原因。

### 验收标准

- 覆盖原版 enum 的文件发现、文件信息和 hash 能力，不含 package ownership。
- 至少新增 SUID/tmp/recent files 三类结构化结果。
- subagent review 无 blocking findings，test subagent 验收通过。

## 10. Phase 8：Package 包归属与软件清单

### 目标

复刻 ATTK rpm/dpkg 包归属能力，并形成软件资产视图。

### 实现模块

```text
internal/collectors/packages/
```

### 功能范围

- dpkg status 解析。
- rpm 查询 fallback。
- 文件路径到 package 归属。
- 包版本、安装状态、架构。
- native command 输出标记为 `native_command`。

### legacy 输出

```text
legacy/enum/dpkg/*.out
legacy/enum/rpm/*.out
```

### ai 输出

```text
ai/evidence.jsonl stream=entities/package
ai/evidence.jsonl stream=facts/file_package_owners
```

### 单元测试

- dpkg status parser。
- rpm output parser。
- 多 package owner 解析。

### 集成测试

- Linux fixture 或真实系统抽样。
- 验证 `/bin/sh`、`/bin/bash` 等路径归属。

### Review 标准

- 直接解析优先，native command fallback 需标记。
- 包归属失败不能影响文件枚举。

### 验收标准

- Debian/Ubuntu 至少 dpkg status 可用。
- RHEL/CentOS rpm fallback 可用。
- package ownership 回填 Phase 7 文件枚举产生的 file artifacts。
- subagent review 无 blocking findings，test subagent 验收通过。

## 11. Phase 9：Browser 浏览器历史

### 目标

复刻 ATTK Chrome/Firefox 历史导出，并保留原始 SQLite 证据。

### 实现模块

```text
internal/collectors/browser/
```

### 功能范围

- Chrome/Chromium profile discovery。
- Firefox profile discovery。
- 复制原始 SQLite DB 到 `ai/raw/`，WAL/SHM 一并复制。
- 解析 history URL/time。
- 可选脱敏 URL query。
- SQLite 方案优先使用纯 Go，避免 CGO 影响 linux/arm64 和 linux/386 交叉编译；若 fallback 到 native `sqlite3`，必须标记 `native_command`。
- locked DB、damaged DB、权限不足均记录错误并保留 raw copy 尝试结果。

### legacy 输出

```text
legacy/browser/chrome/<user>_history.out
legacy/browser/firefox/<user>_history.out
```

### ai 输出

```text
ai/raw/browser/...
ai/evidence.jsonl stream=entities/browser_profile
ai/evidence.jsonl stream=facts/browser_history
ai/evidence.jsonl stream=facts/browser_downloads
ai/evidence.jsonl stream=facts/browser_cookies
ai/evidence.jsonl stream=facts/browser_bookmarks
ai/evidence.jsonl record_type=timeline_event
```

### 单元测试

- Chrome timestamp parser。
- Firefox timestamp parser。
- profile path discovery。
- URL redact。
- WAL/SHM copy strategy。
- damaged/locked SQLite fixture 行为。

### 集成测试

- 使用测试 SQLite DB fixture。
- 验证 legacy 文本和 ai JSONL 同时生成。

### Review 标准

- 原始 DB 复制优先于只查询。
- 浏览器历史标记敏感。
- 查询失败不影响其他模块。
- CGO/native sqlite 决策不破坏 Linux 交叉编译。

### 验收标准

- Chrome/Firefox fixture 均可解析。
- AI 输出含 user、profile、timestamp、url、source db。
- locked/damaged DB fixture 不导致 collector 崩溃。
- subagent review 无 blocking findings，test subagent 验收通过。

## 12. Phase 10：Logs 日志采集与时间线增强

### 目标

补齐原版薄弱的日志采集，将日志统一进入 Phase 1 已提供的时间线 writer，并做排序、归一化和 enriched timeline 输出。

### 实现模块

```text
internal/collectors/logs/
```

### 功能范围

- `/var/log/auth.log`
- `/var/log/secure`
- `/var/log/syslog`
- `/var/log/messages`
- `/var/log/audit/audit.log`
- rotated/compressed logs，例如 `.1`、`.gz`。
- `wtmp`、`btmp`、`lastlog`。
- audit rules，例如 `/etc/audit/rules.d`、`/etc/audit/audit.rules`。
- journal fallback：native `journalctl --output=json`，标记 `native_command`
- cron log。
- SSH 登录、sudo、su、failed password、accepted password/key 基础 parser。

### legacy 输出

```text
legacy/logs/
legacy/autorun/var/log/cron
```

### ai 输出

```text
ai/evidence.jsonl stream=facts/log_events
ai/evidence.jsonl stream=facts/auth_events
ai/evidence.jsonl stream=facts/audit_events
ai/evidence.jsonl record_type=timeline_event
```

### 单元测试

- auth.log parser。
- secure parser。
- sudo/su/ssh event parser。
- timestamp timezone normalization。

### 集成测试

- 使用 fixture 日志。
- 验证 timeline 排序和事件字段。

### Review 标准

- 不采集超大日志全文，需 size/line/time window 策略。
- 日志原文和解析结果可追溯。
- timezone 处理明确。

### 验收标准

- 至少解析 SSH accepted/failed、sudo command、su session。
- timeline JSONL 合法。
- rotated/compressed logs、wtmp/btmp/lastlog/audit rules 有采集或明确 unsupported/absent 记录。
- subagent review 无 blocking findings，test subagent 验收通过。

## 13. Phase 11：Container/Cgroup/Namespace 容器上下文采集

### 目标

补齐现代 Linux 应急响应中容器化环境的关键上下文，将进程、网络、文件路径与容器运行时关联。

### 实现模块

```text
internal/collectors/container/
internal/containerinfo/
```

### 功能范围

- Docker metadata：`/var/lib/docker/containers`、`docker inspect` native fallback。
- containerd metadata：`/run/containerd`、namespace/task 信息。
- Podman/libpod metadata。
- Kubernetes pod/container hints：`/var/lib/kubelet/pods`、CRI metadata。
- `/proc/[pid]/cgroup`、`/proc/[pid]/ns/*`。
- overlay/overlay2 mount 关联。
- container process association。

### legacy 输出

```text
legacy/container/
legacy/container/cgroups.out
legacy/container/namespaces.out
```

### ai 输出

```text
ai/evidence.jsonl stream=entities/container
ai/evidence.jsonl stream=facts/process_containers
ai/evidence.jsonl stream=facts/namespaces
ai/evidence.jsonl stream=facts/cgroups
ai/evidence.jsonl stream=artifacts/runtime_metadata
```

### 单元测试

- cgroup parser。
- namespace symlink parser。
- Docker/containerd/Podman fixture parser。
- overlay mount association。

### 集成测试

```sh
go test ./...
go run ./cmd/dfir-collector --profile phase11-container --output /tmp/dfir-phase11-container
jq -e 'select(.record_type=="collection_event" and .collector=="container")' /tmp/dfir-phase11-container/ai/evidence.jsonl >/dev/null
```

### Review 标准

- native docker/crictl/podman fallback 不能作为唯一证据来源。
- 容器 metadata 缺失时不影响 process/network/files 输出。
- 容器 ID、pod UID、namespace inode 能互相追溯。
- 不读取容器文件系统大目录，除非 profile 明确开启。

### 验收标准

- bare-metal Linux 无容器时记录 absent/skip，不报错。
- 容器 fixture 或真实容器环境能关联 PID -> container。
- deep profile 覆盖 container collector。
- subagent review 无 blocking findings，test subagent 验收通过。

## 14. Phase 12：Archive 归档、完整性与可选加密

### 目标

替代原版简单 `tar.gz`，基于 Phase 1 的 integrity primitives 完成证据链归档 finalize。

### 实现模块

```text
internal/archive/
```

### 功能范围

- tar.gz 基础归档。
- 整包 SHA256/MD5。
- manifest finalize。
- 可选 zip/zstd 后续加入。
- 可选加密后续加入。

### legacy 输出

```text
attk-<session>.tar.gz
```

### ai 输出

```text
ai/manifest.json
ai/archive_summary.json
```

### 单元测试

- tar 创建。
- hash 校验。
- manifest finalize。

### 集成测试

```sh
go run ./cmd/dfir-collector --profile phase12-archive --output /tmp/dfir-phase12-archive
tar tzf /tmp/dfir-phase12-archive.tar.gz
jq -e '.archive.sha256 and .artifact_count' /tmp/dfir-phase12-archive/ai/archive_summary.json
```

### Review 标准

- 归档路径不能包含绝对路径或 `../`。
- manifest 必须在归档前 finalize。
- hash 算法和字段明确。

### 验收标准

- 归档可解包。
- 每个 artifact hash 可复算。
- scanner phase 完成后需要补跑 archive-with-scanner 验收。
- subagent review 无 blocking findings，test subagent 验收通过。

## 15. Phase 13：Scanner Plugins

### 目标

将 `tmbrfix`、YARA、osquery 等作为可选插件接入，不影响主采集链路。

### 实现模块

```text
internal/scanners/tmbrfix/
internal/scanners/yara/
internal/scanners/osquery/
```

### 功能范围

- `tmbrfix` payload 管理。
- scanner hash 校验。
- 架构兼容检查。
- scan-only 默认。
- clean 需要 `--clean confirm|force`。
- stdout/stderr/log/exit code 归档。
- scanner result JSONL。

### legacy 输出

```text
legacy/filescan/
legacy/filerestore/
```

### ai 输出

```text
ai/evidence.jsonl stream=facts/scanner_runs
ai/evidence.jsonl stream=facts/scanner_findings
```

### 单元测试

- scanner compatibility decision。
- args builder。
- log parser。
- timeout handling。

### 集成测试

- 使用 fake scanner fixture，不直接运行危险清理。
- Linux x86/amd64 条件下可做 tmbrfix smoke test：只跑 `-PTNVER`。

### Review 标准

- 默认不清理。
- clean 必须显式参数。
- scanner failure 不影响主采集包生成。
- 外部二进制 hash 记录。

### 验收标准

- `--scan none`、`--scan tmbrfix` 都可运行。
- unsupported arch 会记录 skip reason。
- scanner 输出进入 archive finalize 后的 artifact index。
- 补跑 archive-with-scanner 验收，确认 scanner raw/stdout/stderr/findings 被归档。
- subagent review 无 blocking findings，test subagent 验收通过。

## 16. Phase 14：End-to-End 验收与现场包

### 目标

形成可交付的一次性应急采集包。

### 范围

- Linux amd64 真实环境 E2E。
- Linux arm64 E2E。
- Linux 386 或 amd64 32-bit scanner compatibility 检查。
- 输出包体积、运行时间、权限失败统计。
- README/operator guide。

### 验收命令

```sh
make clean
make linux
./dist/dfir-collector-linux-amd64 --profile quick --output /tmp/dfir-quick
./dist/dfir-collector-linux-amd64 --profile standard --output /tmp/dfir-standard
./dist/dfir-collector-linux-amd64 --profile deep --output /tmp/dfir-deep
./dist/dfir-collector-linux-arm64 --profile minimal-safe --output /tmp/dfir-arm64-smoke
./dist/dfir-collector-linux-386 --scan tmbrfix --profile minimal-safe --output /tmp/dfir-386-scanner-smoke
```

### 最终验收标准

- quick profile 可在 5-10 分钟内完成。
- standard profile 可在默认限制内完成。
- deep profile 覆盖 container 和 scanner skip/compatibility 语义。
- linux/arm64 runtime smoke 通过。
- linux/386 scanner compatibility smoke 通过或给出明确环境限制说明。
- 生成 legacy 和 ai 双轨输出。
- manifest 完整。
- JSON/JSONL 全部可解析。
- 原始 ATTK 外层采集面被覆盖或有明确说明。
- subagent review 无 blocking findings，test subagent 验收通过。

## 17. Phase 执行模板

每次开始 phase 前，主 agent 应输出：

```text
Phase:
Scope:
Files/modules:
Expected legacy output:
Expected ai output:
Tests:
Acceptance:
```

每次完成 phase 后，启动 subagent：

```text
Review subagent prompt:
请独立审查 Phase X 的实现。重点看采集逻辑、证据可信度、路径安全、schema 一致性、权限失败处理、是否有系统修改副作用。不要修改代码，输出 findings 和 blocking/non-blocking 分类；blocking 必须给出文件/行号，non-blocking 必须说明 residual risk。

Test subagent prompt:
请独立测试 Phase X 的实现。在 forked workspace 中运行 go test ./...、make linux、phase 验收命令、JSON/JSONL jq 校验、legacy 非空断言，并至少跑一次 non-root smoke test。不要修改代码，输出 pass/fail、失败命令和关键日志。
```

主 agent 最终汇报格式：

```text
Phase X completed
Changed files:
Local verification:
Review subagent:
Test subagent:
Residual risks:
Next phase:
```
