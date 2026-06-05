# Go ATTK Collector 总路线图

更新时间：2026-06-05

本文是 Go ATTK / Linux DFIR collector 的主 roadmap。`PHASE_STATUS_CN.md` 已转为 Phase 1-14 的历史执行留档；后续采集器实现进度、缺口、优先级和验收标准以本文为准。Parser / AI agent 的需求池见 `PARSER_REQUIREMENTS_CN.md`。

## 固定边界

- Collector 只做事实采集、轻量结构化、证据链记录和打包。
- Collector 不做风险判断、攻击归因、恶意结论、处置建议或报告生成。
- 所有 AI 结构化事实进入单一 `ai/evidence.jsonl`，通过 `stream`、`collector`、`record_type`、`source_*` 字段区分。
- `legacy/` 和 `ai/raw/` 用于人工复核和证据保全，后续开发只增不减。
- Collector 不写 `risk`、`severity`、`verdict`、`malicious`、`suspicious` 等分析字段。

## 状态定义

| 状态 | 含义 |
|---|---|
| 已完成 | 已进入 AI JSONL，字段粒度足够支撑初步 parser / AI 分析，并保留 legacy/raw 复核面 |
| 部分覆盖 | 已采集或部分结构化，但字段粒度、发行版覆盖或关联字段仍不足 |
| 仅留原文 | legacy/raw 已保留，但 AI JSONL 尚不能直接消费 |
| 缺失 | 尚未覆盖 |
| 计划中 | 已列入路线，尚未开始实现 |

## 已完成基线

从 `PHASE_STATUS_CN.md` 提取的当前 collector 已实现进度如下。Phase 1-14 均已完成，原版 ATTK 非扫描采集 legacy 对比已补齐到 `missing_or_partial=0`。

| 模块 | 当前状态 | 已实现内容 | 仍需后续增强 |
|---|---|---|---|
| 工程骨架 / 输出框架 | 已完成 | CLI、profile、`legacy/` + `ai/`、manifest、artifact index、collection log、timeline、errors、schema、archive summary | 输出框架错误传播和超时细粒度治理 |
| 主机 / 系统 / 用户 / 磁盘 / 时间 | 已完成 | 主机基础信息、OS、kernel、users/groups、SSH host key metadata、mount/time、文件 metadata timeline | privileged/login_capable 等账户事实可增强 |
| 内核 | 已完成 | `/proc/modules`、`/sys/module`、cmdline、tainted、kernel module entities、module metadata | rootkit 一致性事实、module signature、lockdown/LSM/sysctl 深化 |
| 进程 | 已完成 | `/proc/[pid]` 直接采集、cmdline/environ summary/exe/cwd/root/maps/fd、legacy ps/lsof 合成、权限/race 记录 | process lineage、session/tty、start_time、container/cgroup/ns 合并 |
| 网络 | 已完成 | `/proc/net` socket/route/arp/interface、socket inode -> PID/FD、hosts/resolv、firewall status、conntrack、flow enrichment、proxy/tunnel config | DHCP leases、proc net counters、DNS runtime、native command cross-check |
| 持久化 | 已完成 | cron、rc/init、system/user systemd、drop-in/enabled symlink、SSH authorized_keys/config、shell profile、sudoers、loader、at、XDG autostart、私钥 redaction | PAM persistence、anacron/at 语义、init script 命令、service manager 兼容项 |
| 文件枚举 | 已完成 | 模块文件、打开文件、autorun 文件、SUID/SGID、tmp/recent、webroot、hash、package owner、file flags、collector artifact 过滤 | xattr/capability/immutable/append-only、btime、关键文件 mutation timeline |
| 软件包 | 已完成 | dpkg/rpm 包清单、dpkg multi-arch、md5sums、rpm native fallback、文件包归属 | package integrity verify、conffiles、expected/actual hash、RHEL rpm 变体实测 |
| 浏览器 / 历史记录 | 已完成 | Chrome/Chromium/Firefox profile discovery、SQLite raw copy + WAL/SHM、history/download/cookie/bookmark JSONL | live locked DB、其他用户权限、Firefox 版本差异 VM 补测 |
| 日志 | 已完成 | auth/secure/syslog/messages/audit、rotated/compressed、wtmp/btmp/lastlog 结构化、ISO8601/classic syslog、timeline | journal events、audit rules absent fact、跨年 rotated log 时间推断 |
| 容器 / Cgroup / Namespace | 已完成 | Docker/containerd/Podman/Kubernetes/CRI-O cgroup/ns/runtime metadata 关联、container facts/artifacts | overlay mount、host path mount、image digest、rootless runtime 实测 |
| 归档 | 已完成 | tar.gz、整包 hash、manifest finalize、archive summary、路径安全校验、`--archive` | 真实大采集耗时/权限/跨文件系统输出补测 |
| 扫描插件 | 已完成 | scanner framework、scan none/tmbrfix/yara/osquery、tmbrfix payload hash/compatibility、stdout/stderr raw/legacy、scanner facts | 真实 tmbrfix/yara/osquery Linux 执行补测；默认仍不启用扫描 |
| 端到端验收 | 已完成 | quick/standard/deep/minimal-safe smoke、JSONL parse、manifest/archive、Linux arm64 VM deep `--scan none`、原版 ATTK vs Go 非扫描对比 | amd64/RHEL/container/scanner 真实环境矩阵补测 |

## 当前代码状态快照

本节用于把“代码已经实现的 stream”和“后续增强计划”分开，避免把已做首轮的 P0 能力误读为完全缺失。

| 能力 | 当前代码状态 | 已有 AI stream / 字段 | 仍需开发 |
|---|---|---|---|
| 会话观察 | 首轮已实现，仍需合并进程上下文 | `facts/session_observations`，覆盖 auth/audit、wtmp/btmp/utmp/lastlog、sudo actor/target/cwd/command、`login_session_id` | 与 `/proc/[pid]` start_time、session、tty、cgroup/container/ns 合并 |
| 包完整性事实 | 首轮已实现，Debian/Ubuntu 优先 | `facts/package_integrity`，覆盖 dpkg `.list`、`.md5sums`、`.conffiles`、expected/actual hash、existence、size、mode、uid/gid、mtime | RHEL/rpm verify 真实变体、关键命令目录合并、更多 package owner 交叉事实 |
| 内核安全 / 一致性 | 首轮已实现 | `facts/kernel_security`、`facts/kernel_consistency`，覆盖 module/proc/sysfs、module file hash、taint、lockdown、LSM、sysctl | module signature、secureboot hint、package owner、proc/sysfs 深层一致性 |
| PAM 持久化 | 首轮已实现 | `facts/pam_persistence`，覆盖 `/etc/pam.d/*` 行解析、模块路径解析、hash/size/mode | module package owner、symlink target、include/substack 关联、发行版路径补测 |
| Cron / 周期脚本 | 首轮已实现 | `facts/cron_entries`，覆盖 schedule/user/command、target_path、target_exists、target_mode、target_uid/gid、target_size、target_sha256 | interpreter 深层脚本、package owner、mtime |
| Journal 事件 | 首轮已实现，待 Linux VM 真实 journal 补测 | `facts/journal_events`，覆盖 journal JSON event、absent/error/status、raw/legacy journalctl stdout、`raw_copy_ref` | timeout/empty/超长行/多值字段变体补测；真实 Linux journal 权限和输出变体补测 |
| 进程谱系 | 部分覆盖，尚无专用合并 stream | 已有 `entities/process`、socket owner、container/cgroup/ns 原始事实 | 新增 `facts/process_lineage` 合并父子链、start_time、session、tty、exe hash/package、container/cgroup/ns |
| 文件属性 / 变更 | 部分覆盖，尚无专用属性 stream | 已有 `entities/file`、`facts/file_hashes`、`facts/file_flags`、timeline | 新增/增强 xattr、capability、immutable、append-only、statx/btime、关键文件 mutation timeline |

## 当前采集缺失与优先级

下面是当前 collector 后续缺口的总表。优先级按“对一次性应急采集 + AI 原生 parser 后续分析”的价值排序。表中只描述 collector 应采集的事实，不描述 parser 后续应输出的风险结论。

| 优先级 | 能力 | 当前状态 | 是什么 / 采什么 | 主要采集位置 | DFIR 价值 | 建议 stream |
|---|---|---|---|---|---|---|
| P0 | 会话观察 | 部分覆盖 | 当前登录会话、历史登录、sudo 会话和 TTY 的可关联事实字段，例如 user、remote、tty、pid、`login_session_id`、sudo target_user、command cwd；首轮已输出 `facts/session_observations`，覆盖 auth/audit 日志和 wtmp/btmp/utmp/lastlog 派生事实 | `/var/run/utmp`、`/var/log/wtmp`、`/var/log/btmp`、`/var/log/lastlog`、`/var/log/auth.log`、`/var/log/secure`、`/proc/[pid]` | 帮 parser 还原“谁从哪里登录、切到什么权限、执行了什么命令”，是时间线和入侵入口分析的核心；下一步继续合并 `/proc/[pid]` 的 start_time、session、tty、cgroup/container 上下文 | `facts/session_observations` |
| P0 | 包完整性事实 | 部分覆盖 | 包数据库中的 expected hash、磁盘实际文件 hash、mtime、owner、存在性和权限元数据事实 | Debian/Ubuntu: `/var/lib/dpkg/status`、`.list`、`.md5sums`、`conffiles`；RHEL: rpmdb、`rpm -Va`；关键目录 `/bin`、`/sbin`、`/usr/bin`、`/usr/sbin` | 应对命令替换、系统工具被感染、包文件被删除或篡改；collector 只记录可复核事实，不判断恶意 | `facts/package_integrity` |
| P0 | 内核一致性观察 | 部分覆盖 | 内核模块和内核安全状态的一致性事实，例如 loaded module、module file、hash、package、taint、lockdown、LSM/sysctl；module signature 作为后续增强 | `/proc/modules`、`/sys/module`、`/lib/modules/<kernel>`、`modules.dep`、`/proc/sys/kernel/*`、`/sys/kernel/security/*` | 支撑 rootkit 线索排查，发现 proc/sysfs/module 文件之间的不一致；collector 不输出 rootkit 结论 | `facts/kernel_consistency`、`facts/kernel_security` |
| P0 | PAM 持久化 | 部分覆盖 | PAM 配置中的执行型或自定义模块事实，例如 `pam_exec.so`、`pam_python.so`、`pam_script.so`、非系统路径 `.so`、参数、hash；首轮已输出 `facts/pam_persistence`，覆盖 `/etc/pam.d/*` 行解析、模块路径解析、模块文件 hash/size/mode；package owner 后续增强 | `/etc/pam.d/*`、相关 PAM module 路径如 `/lib/security`、`/lib64/security`、`/usr/lib/security`、`/usr/lib64/security`、`/usr/lib/*/security` | PAM 是高价值持久化入口，攻击者可在登录、sudo、ssh 等认证流程中挂执行逻辑 | `facts/pam_persistence` |
| P0 | Cron / 周期脚本增强 | 部分覆盖 | cron 入口已采到 schedule/user/command；首轮已把命令首个绝对路径和周期脚本自身关联为 target_path、target_exists、target_mode、target_uid/gid、target_size、target_sha256；interpreter 深层脚本、package owner、mtime 后续增强 | `/etc/crontab`、`/etc/cron.d/*`、`/etc/cron.hourly`、`/etc/cron.daily`、`/var/spool/cron*`、脚本实际路径 | cron 是最常见 Linux 持久化方式之一；把入口和脚本文件直接关联，AI 后续无需回翻 raw | 增强 `facts/cron_entries` |
| P1 | Journal 事件 | 已完成首轮 | systemd journal 事件结构化，例如 unit、pid、uid、boot_id、priority、message、timestamp；命令不可用、权限不足、失败或 JSON 损坏时输出 status/error fact；stdout 保留 raw/legacy 复核副本 | `journalctl -o json --no-pager`、`/var/log/journal`、`/run/log/journal` | 现代 Linux 大量服务启动、失败、重启、登录和安全事件只在 journal 里完整出现，可补 syslog 缺口 | `facts/journal_events` |
| P1 | 进程谱系事实 | 部分覆盖 | 进程父子链、start_time、session、tty、exe hash/package、namespace/cgroup/container 的合并事实 | `/proc/[pid]/stat`、`status`、`cmdline`、`exe`、`cwd`、`fd`、`cgroup`、`ns/*` | 帮 parser 从孤立进程记录升级为执行链，关联登录、sudo、网络外联和落地文件 | `facts/process_lineage` |
| P1 | 文件变更 / 属性 | 部分覆盖 | 文件变化和扩展属性事实，例如 mtime/ctime/btime、xattr、capability、immutable、append-only、hash、package owner | 关键系统目录、webroot、tmp/dev_shm、persistence 指向文件、SUID/SGID 文件；可用 `statx`、xattr、capability、fs flags | 排查 webshell、落地文件、命令替换、权限隐藏和防删除手段；collector 只记录属性和时间事实 | `facts/file_attributes`、`facts/file_timeline` |
| P1 | DHCP 租约 | 仅留原文 | DHCP 分配事实，例如 lease IP、router、DNS、DHCP server、lease start/end、interface | `/var/lib/dhcp/*`、`/var/lib/dhclient/*`、NetworkManager lease 目录 | 还原主机所在网络、历史 IP、DNS 和网关，辅助横向移动、资产定位和时间线解释 | `facts/dhcp_leases` |
| P1 | DNS 运行时解析器 | 缺失/部分覆盖 | 运行时 DNS 配置和 resolver 状态，例如 resolved、NetworkManager、dnsmasq 当前 nameserver/search/cache source | `/etc/resolv.conf`、systemd-resolved runtime、NetworkManager runtime、dnsmasq 配置和 lease/cache 文件 | DNS 被篡改或代理化会影响外联和下载路径；运行时 DNS 常与静态 resolv.conf 不一致 | 增强 `facts/dns_config` |
| P1 | 原生命令交叉观察 | 仅留原文 | 系统命令输出与 Go-native/procfs 采集结果的交叉观察事实，并记录命令路径、hash、package owner | `ip`、`ss`、`netstat`、`lsof`、`route`、`arp`、`ps` 等可用命令及其二进制路径 | 当系统命令可能被替换时，差异事实可给 parser 提供复核线索；collector 不判定篡改 | `facts/command_observations` |
| P1 | at/anacron 语义化 | 部分覆盖 | at/anacron 计划任务的执行时间、执行用户、命令体、环境和目标脚本事实 | `/var/spool/at*`、`/etc/anacrontab`、`/var/spool/anacron` | at/anacron 可作为一次性或延迟执行持久化入口，常被忽略 | 增强 `facts/persistence_items` |
| P1 | rc/init/upstart 命令提取 | 部分覆盖 | 老式 init/rc/upstart 的启动入口、runlevel、脚本命令、脚本 hash/package owner | `/etc/rc.local`、`/etc/init.d/*`、`/etc/rc*.d/*`、`/etc/init/*.conf`、`/etc/inittab` | 兼容非纯 systemd 或老系统，补齐服务自启动和启动脚本入口 | 增强 `facts/persistence_items` |
| P2 | 容器挂载事实 | 部分覆盖 | 容器挂载和 overlay 事实，例如 lower/upper/workdir、host bind mount、image digest、runtime config | Docker/containerd/Podman runtime metadata、`/proc/[pid]/mountinfo`、overlayfs 路径、Kubernetes/CRI metadata | 容器逃逸、挖矿和主机路径挂载调查需要知道容器与宿主文件系统关系 | `facts/container_mounts` |
| P2 | proc/net 计数器 | 仅留原文 | 网络计数器事实，例如 TCP/UDP/SNMP counters、错误包、重传、连接统计 | `/proc/net/snmp`、`/proc/net/snmp6`、`/proc/net/netstat` | 作为网络异常和流量状态的上下文补充，通常不决定初筛结论 | `facts/network_counters` |
| P2 | 云 / 虚拟化线索 | 计划中 | 云和虚拟化资产事实，例如 DMI、cloud-init、instance-id、provider hint、metadata route hint | `/sys/class/dmi/id/*`、`/var/lib/cloud/*`、cloud-init 配置、路由表中的 metadata 地址 | 帮助定位云主机资产、镜像来源和实例身份，辅助报告和后续处置 | `entities/cloud_instance` |
| P2 | 服务管理器兼容项 | 缺失/部分覆盖 | 非 systemd 服务管理器和应用级 scheduler 的启动项事实 | OpenRC、runit、supervisord、s6、应用自带 scheduler 配置 | 覆盖 Alpine、嵌入式、老发行版或特殊业务主机的自启动入口 | 增强 `facts/persistence_items` |

## 后续开发计划

### Phase A1：Journal 事件结构化

目标：补齐现代 Linux 的 systemd journal 事件事实，输出 `facts/journal_events`。

当前进展：

- 状态：已完成首轮实现。
- DEV 子 agent：PASS，完成 `internal/collectors/logs` journal event 采集和 fixture 单测。
- Review 子 agent：先 FAIL 后 PASS；blocking 为 private key block body 脱敏不足，已通过 `internal/redact` 整段 private key block redaction 修复并补测试。
- Test 子 agent：PASS，覆盖 `go test ./internal/collectors/logs -count=1`、`go test ./...`、字段边界扫描、`git diff --check`、fake `journalctl` CLI smoke、JSONL 校验。
- Main agent：完成 roadmap 对齐、raw/legacy journal stdout 保全、非法 JSON 状态去重、最终集成验收。

Collector 工作：

- 优先执行 `journalctl -o json --no-pager`，采集 stdout raw/legacy 复核面。
- 解析 journal JSON 字段：timestamp、unit、pid、uid、gid、boot_id、priority、message、syslog_identifier、transport、cursor、monotonic timestamp 等存在字段。
- `journalctl` 不存在、权限不足、返回错误、无事件或 JSON 行损坏时，输出明确 `facts/journal_events` status/error fact。
- 对 message、command-like 字段使用统一脱敏；AI 结构化输出会整段替换 PEM/OpenSSH private key block，raw/legacy 保留原文用于证据保全。

验收：

- fixture 覆盖正常 JSON、缺失命令、命令失败、非法 JSON。
- `go test ./internal/collectors/logs -count=1` 和 `go test ./...` 通过。
- 不出现风险/结论字段。
- 已用 fake `journalctl` 完成 mac CLI smoke：合法 JSONL、`facts/journal_events`、`raw_copy_ref`、raw/legacy journal stdout、parse_error 状态均正常。
- Ubuntu ARM64 VM 后续 deep `--scan none` 抽样验证真实 systemd journal runtime；当前 mac 无法验证真实 journal 权限和输出变体。

### Phase A2：Process Lineage

目标：把已有 `entities/process`、session、network owner、container/cgroup/ns 事实合并为 AI 更易消费的 `facts/process_lineage`。

Collector 工作：

- 基于 `/proc/[pid]/stat`、`status`、`cmdline`、`exe`、`cwd`、`fd`、`cgroup`、`ns/*` 输出 ppid tree、start_time、session、tty、exe hash/package、container/cgroup/ns。
- 与 socket owner、session_observations 通过稳定 key 关联，但不输出攻击链结论。

验收：

- fixture 覆盖父子进程、session/tty、exe hash、cgroup/ns。
- parser 可以从 JSONL 构建进程执行图，不需要回读 legacy ps/lsof。

### Phase A3：File Attributes / Timeline

目标：补齐命令替换、webshell、SUID 后门和不可变属性排查所需文件事实。

Collector 工作：

- 对关键系统目录、webroot、tmp/dev_shm、persistence 指向文件、SUID/SGID 文件采集 xattr、capability、immutable、append-only、statx/btime fallback、hash、package owner。
- 输出 `facts/file_attributes`，必要时增强 `facts/file_timeline`。

验收：

- fixture 覆盖 capability、xattr、immutable/append-only、btime fallback。
- 不输出“异常/恶意”判断，只输出属性和时间事实。

### Phase B：会话观察深化

目标：补齐登录、sudo、TTY、session、进程的可关联事实字段。

当前进展：

- 已实现首轮 `facts/session_observations`，从 auth/secure/audit 日志、wtmp/btmp/lastlog 和 `/var/run/utmp` 生成统一会话观察事实。
- 已结构化 sudo command 的 `actor_user`、`target_user`、`tty`、`cwd`、`command`，并沿用脱敏后的命令内容。
- 已为登录会计记录输出 `login_session_id` 并生成候选 `session_key`，用于后续 parser 关联同一 user/remote/tty/session/pid；`login_session_id` 避免和 evidence envelope 的采集 `session_id` 元数据重名。
- 待继续增强：把 `/proc/[pid]` 的 start_time、session、TTY、cgroup/container/ns 上下文合并进同一会话观察或进程谱系事实。

Collector 工作：

- 为 `facts/login_events`、`facts/auth_events` 增加稳定 `session_key` / `auth_chain_key` 候选字段。
- 解析当前登录会话：`/var/run/utmp`、TTY、remote host、pid。
- 把 sudo command/session 与 user、TTY、cwd、timestamp、target_user 结构化对齐。
- 在 timeline 中保留事实事件，不输出链路结论。

验收：

- fixture 覆盖 SSH accepted/failed、sudo command、sudo session open/close、wtmp/btmp/utmp。
- Ubuntu VM deep 输出中，同一 user/remote/tty/pid 能被 parser 后续关联。
- 不出现风险/结论字段。

### Phase C1：包完整性事实

目标：为命令替换、系统文件变化提供可复核事实。

当前进展：

- 已实现 dpkg 首轮 `facts/package_integrity`，基于 `.list`、`.md5sums`、`.conffiles` 输出 package、path、expected_md5、actual_md5、hash_available、file_exists、size、mode、uid、gid、mtime、package_conffile 等事实。
- 已保留原有 `entities/package` 和 `facts/file_package_owners`，包清单和文件归属能力只增不减。
- 待继续增强：RPM `rpm -Va` / rpmdb verify flags、关键命令目录 owner/hash 合并、VM/RHEL 实测矩阵。

Collector 工作：

- dpkg：解析 `status`、`.md5sums`、`conffiles`、`.list`，输出 expected hash、actual hash、hash availability、file existence 和文件元数据。
- rpm：支持 `rpm -Va` / rpmdb 文件归属，记录 verify flags 和文件元数据。
- 对关键命令目录 `/bin`、`/sbin`、`/usr/bin`、`/usr/sbin` 合并 package owner/hash。
- 工具不存在或权限不足时输出 absent/error fact。

验收：

- Debian/Ubuntu fixture + VM 验证 dpkg hash 对比。
- RHEL-family 后续 VM 验证 rpm 输出变体。
- `facts/package_integrity` 只记录校验事实，不写恶意判断。

### Phase C2：内核一致性观察

目标：为 rootkit 排查提供一致性事实。

当前进展：

- 已实现首轮 `facts/kernel_security`，输出 cmdline、tainted、lockdown、LSM、AppArmor、SELinux 和关键 kernel sysctl 的事实值或 absent fact。
- 已实现首轮 `facts/kernel_consistency`，对 loaded module / sysfs module 输出 module_name、loaded、proc_modules_present、sysfs_present、sysfs_path、module_path、module_file_exists、module_file_size、module_file_sha256、holders、refcount、source_facts 等事实。
- 已保留原有 `entities/kernel_module`、legacy modules/cmdline/tainted/modinfo/modprobe 输出和 timeline 行为。
- 待继续增强：module signature fields、secureboot hint、package owner、proc/sysfs 深层一致性、PID/socket/cgroup namespace 交叉引用。

Collector 工作：

- 对比 `/proc/modules`、`/sys/module`、`/lib/modules/<release>`、`modules.dep`。
- 对 loaded module 输出 path、hash、package owner、modinfo、refcount、taint relation；signature fields 进入后续增强。
- 采集 kernel taint、lockdown、secureboot hint、LSM/AppArmor/SELinux status、关键 sysctl。
- 初步 process/socket/cgroup 一致性事实：PID 目录、task、socket owner、namespace/cgroup 是否能互相引用。

验收：

- fixture 覆盖 module present/missing、sysfs/procfs 来源字段、module file hash/size、kernel security facts、taint。
- VM deep 输出包含 `facts/kernel_consistency`，无 rootkit verdict。

### Phase C3：PAM + Journal

目标：补齐 Linux 持久化和现代日志关键缺口。

当前进展：

- 已实现 PAM 首轮 `facts/pam_persistence`，解析 `/etc/pam.d/*` 的 pam_type、control、module、module_args、line_number、service、source_file。
- 已对绝对路径模块和常见 PAM module 目录中的裸模块名做 best-effort resolve，输出 module_path_resolved、module_file_exists、module_file_sha256、module_file_size、module_file_mode。
- 已保留 PAM 配置文件的 `entities/persistence_file` 和 legacy copy，用于人工复核。
- 待继续增强：PAM module package owner、symlink target hash、更多发行版 PAM module 目录、include/substack 语义关联、Journal 事件结构化。

Collector 工作：

- PAM：解析 `/etc/pam.d/*`，提取 pam_exec/pam_python/pam_script/custom module 路径、参数、hash、package owner。
- Journal：优先 `journalctl -o json --no-pager`，无权限或缺失时输出 absent/error；解析 unit、pid、uid、gid、boot_id、priority、message、timestamp。

验收：

- PAM fixture 覆盖常见 module 行和自定义 `.so`。
- Ubuntu VM 上有 `facts/journal_events` 或明确 absent/error。

### Phase D：进程 / 文件 / 容器深化

目标：让 parser 能从单一 `evidence.jsonl` 更稳定地串联主机上下文。

Collector 工作：

- 进程 lineage：ppid tree、session、tty、start_time、exe hash/package、container/cgroup/ns。
- 文件属性：xattr、capability、immutable、append-only、btime fallback。
- 容器 mount：overlay、bind mount、host path、image digest、runtime config raw metadata。

验收：

- parser 可以不回读 legacy/raw，先从 JSONL 构建登录、执行、持久化、网络、文件、容器事实图。

## Linux VM / 发行版补测矩阵

| 环境 | 状态 | 目标 |
|---|---|---|
| Ubuntu ARM64 UTM | 已完成当前 deep 非扫描验收 | 已完成 deep `--scan none` JSONL 质量验收 |
| Ubuntu/Debian amd64 | 计划中 | amd64 真实 runtime、dpkg integrity、journal、browser active DB |
| RHEL/CentOS/Rocky/Alma | 计划中 | rpm verify、secure/messages、SELinux、firewalld/nft/iptables 输出变体 |
| 容器宿主机 | 计划中 | Docker/containerd/Podman/CRI-O/Kubernetes、overlay、rootless runtime |
| 扫描器运行时 | 计划中 | tmbrfix i386/amd64 32-bit compatibility、YARA/osquery execution、timeout/permission |

## Gate 要求

- 每个 collector phase 必须保留 Dev / main integration / review / test gate。
- 每个新增 stream 必须进入单一 `ai/evidence.jsonl`。
- 每个 parser 所需字段必须有 fixture 单测和 VM 抽样验证。
- Linux-only 能力必须标记 mac 无法验证项，并在 UTM VM 或后续 amd64/RHEL VM 中补测。
