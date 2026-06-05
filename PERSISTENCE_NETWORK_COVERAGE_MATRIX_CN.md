# Persistence / Network 覆盖矩阵

更新时间：2026-06-04

范围：下一阶段先做 `1/2`，即持久化增强与网络外联增强。本文只记录技术点、当前覆盖状态、优先级和落地目标；不改变“只采事实、不做分析结论、单一 `ai/evidence.jsonl`”原则。

## 本轮落地结果

当前 P0 持久化与网络外联增强已完成首轮实现、独立 review/test gate 和 Ubuntu ARM64 VM `deep --scan none` 验证：

- Persistence：systemd directive/drop-in/enabled symlink、shell profile、loader、SSH authorized_keys/options、sshd_config、sudoers 已进入 AI 结构化输出。
- Network：interface IPv4/MAC/MTU/flags、hosts/resolv、socket owner enrichment、process/exe hash/package、network flows、conntrack absent/entry、nft/iptables parser、proxy/tunnel config 已进入 AI 结构化输出。
- Cross-cutting：新增 `internal/redact`，AI 结构化字段会脱敏常见 token/password/private key/API key/PSK、URL credential/query secret、quoted secret、process/network owner cmdline、auth/audit log message/command/fields、private-key marker。
- 输出边界：AI 主输出仍只有 `ai/evidence.jsonl`；`legacy/` 与 `ai/raw/` 保留原文复核，不作为本轮结构化脱敏边界。
- VM 产物：Mac 副本 `/tmp/dfir-pn-review-final/evidence.jsonl`；VM 产物 `/tmp/dfir-pn/out/ai/evidence.jsonl`。

状态定义：

- Done：已进入 AI JSONL 且字段足够支撑初步 AI 分析。
- Partial：已采集或部分结构化，但字段粒度不足。
- LegacyOnly：有 legacy/raw 证据，AI JSONL 尚不能直接消费。
- Missing：尚未覆盖。

## 持久化

| 技术点 | 当前状态 | 当前已有能力 | 主要缺口 | 优先级 | 建议输出 |
|---|---|---|---|---|---|
| cron 系统任务 | Done | `/etc/crontab`、`/etc/cron.d/*`、周期目录、spool cron；已提取 schedule/user/command/path/line | periodic script 只记录脚本路径，未解析脚本内容/interpreter/hash | P0 | 增强 `facts/cron_entries` |
| at/anacron | Partial | at spool 目录、allow/deny 文件、首条有效命令 | anacrontab 未专门解析；at job header/执行用户/时间未结构化 | P1 | `facts/persistence_items` |
| rc/init/upstart | Partial | `/etc/rc.local`、`/etc/inittab`、`/etc/init*`、rc*.d symlink hint | init script 内部命令未结构化；runlevel 关系粗略 | P1 | `facts/persistence_items` |
| systemd unit discovery | Done | system/user unit 目录、user unit、unit 文件复制；unit/type/path；`ExecStart*`/`ExecReload`/`ExecStop`/`ExecCondition`、Environment、User/Group、WorkingDirectory、Restart、Requires/Wants/After/Before、timer/path/socket 触发链 | 复杂变量展开和 unit merge 顺序仍保持事实采集，不做解释执行 | P0 | 增强 `entities/systemd_unit` |
| systemd drop-in override | Done | `/etc/systemd/system/*.d/*.conf`、user drop-in 作为 drop-in item 采集，保留 path/unit/directive 事实 | 未模拟 systemd 最终 merge 后有效配置 | P0 | 并入 `entities/systemd_unit` |
| systemd 启用状态 | Done | `.wants/.requires` symlink、masked `/dev/null` symlink、Install WantedBy/RequiredBy hint | runtime enabled 仍不调用 systemctl 解释 | P0 | `facts/persistence_items` / `entities/systemd_unit` |
| SSH authorized_keys | Done | key type、fingerprint、options、comment、user、path/line；已拆 `command/from/environment/permitopen/no-pty` | 不输出公钥 blob；不做权限风险判断 | P0 | 增强 `facts/persistence_items` |
| SSH config / sshd_config | Done | `/etc/ssh`、用户 `.ssh/config` 指令 keyword/values，覆盖 `AuthorizedKeysCommand`、`ForceCommand`、ProxyCommand 等事实 | `Match` block 作用域暂不解释 | P0 | `facts/persistence_items` |
| 私钥/host key | Done | 私钥内容不复制，输出 metadata/redacted；host/user key 文件元数据 | 可补 fingerprint/public key 派生，但需避免泄露敏感内容 | P2 | `entities/persistence_file` |
| shell profile | Done | `/etc/profile`、`/etc/bash.bashrc`、`/etc/zsh/zshenv`、`/etc/zsh/zprofile`、`/etc/profile.d/*`、用户 `~/.profile`、`~/.bashrc`、`~/.bash_profile`、`~/.bash_login`、`~/.zshrc`、`~/.zprofile`、`~/.zshenv`、`~/.config/fish/config.fish`；结构化 `export/PATH/LD_PRELOAD/LD_LIBRARY_PATH/LD_AUDIT`、alias、source、exec-like 行 | function body 和复杂 shell 语义不解释执行 | P0 | `facts/persistence_items` |
| sudoers | Done | `/etc/sudoers`、`/etc/sudoers.d`；解析 include、subject、hosts、RunAs、NOPASSWD/SETENV 等 tags、命令列表 | 复杂 alias 展开和续行仍为 best-effort | P0 | `facts/persistence_items` |
| XDG autostart | Done | system/user autostart `.desktop`，解析 Exec/Name/Hidden | 缺 TryExec、OnlyShowIn/NotShowIn、Terminal、X-GNOME-Autostart-enabled | P1 | 增强 `facts/persistence_items` |
| PAM 持久化 | Missing | 无专门扫描 | `/etc/pam.d/*` 中 `pam_exec.so`、`pam_python.so`、`pam_script.so`、自定义 `.so` 路径/hash | P0 | `facts/pam_persistence` |
| dynamic loader 持久化 | Done | `/etc/ld.so.preload`、`/etc/ld.so.conf`、`/etc/ld.so.conf.d/*`、profile 中 `LD_PRELOAD/LD_LIBRARY_PATH/LD_AUDIT`；目标路径 metadata/hash | package owner 可后续补齐 | P0 | `facts/persistence_items` |
| service manager 兼容项 | Missing/Partial | systemd/rc/upstart 部分覆盖 | OpenRC、runit、supervisord、cron-like app scheduler 未覆盖 | P2 | `facts/persistence_items` |

## 飞书排查文档对照

参考文档：`https://asiainfo-sec.feishu.cn/docx/WwsTdL1V5odp4xxqEWFcMQCVnig`

文档对当前设计有帮助，主要是把人工排查经验转成采集需求：

| 文档提到的排查点 | 当前覆盖 | 需要转化的增强 |
|---|---|---|
| `/proc/{PID}/cmdline,cwd,environ,exe,mem` | process 已采 cmdline/cwd/environ summary/exe/fd/maps；不采 mem | 外联 flow 中合并 PID 的 exe/cmdline/cwd/hash/package；继续不采集进程内存，避免体积和敏感风险 |
| `~/.bash_profile` 可被加自启动命令 | 已覆盖用户 `~/.bash_profile` 和同类 shell profile | 把非注释行进一步解析为 `export/alias/function/source/exec` 类型，特别标出 `PATH/LD_PRELOAD/LD_LIBRARY_PATH` 字段事实 |
| `LD_PRELOAD` 与 `/etc/ld.so.preload` | profile 行可能记录到；`/etc/ld.so.preload` 尚未语义化 | 新增 loader persistence：读取 `/etc/ld.so.preload`、解析目标 `.so`、hash、package owner、mtime/ctime |
| 计划任务 | cron 已结构化 | 对 periodic script 增加 interpreter/hash/package owner；补 anacron |
| `last/lastb/who/w/uptime` | wtmp/btmp/lastlog 已结构化，系统 uptime 已在 system/time 面 | 可补当前登录会话 `utmp`/`who` 等价事实，关联 TTY、remote、process session |
| 账户分析：UID 0、可远程登录账户、sudoers | users/groups 已采，sudoers 有有效行 | users 模块补 privileged/login_capable 字段；sudoers 解析 subject/runas/NOPASSWD/SETENV/command |
| netstat/lsof 外联定位 PID，再查 `/proc/PID/exe` | socket + PID/FD owner 已有，process exe 已有 | 增加 `facts/network_flows` 合并 socket + process + exe hash + package + user/container |
| lsattr/chattr 文件属性 | file_flags 有部分文件标志，但 immutable/append-only 需要确认覆盖深度 | 对关键文件/落地文件补 xattr/capabilities/immutable/append-only 结构化事实 |

## 网络外联

| 技术点 | 当前状态 | 当前已有能力 | 主要缺口 | 优先级 | 建议输出 |
|---|---|---|---|---|---|
| TCP/UDP socket | Done | `/proc/net/tcp,tcp6,udp,udp6`，local/remote/state/uid/inode，owner PID/FD/process_name | 未合并进程 exe/cmdline/hash/package/container/cgroup；未显式方向分类 outbound/listener/public/private | P0 | 增强 `entities/socket` |
| Unix socket | Done | `/proc/net/unix` path/type/flags/inode/owner | 未关联服务/进程 hash/package；抽象 namespace socket 语义较少 | P1 | 增强 `entities/socket` |
| socket owner | Done | 扫 `/proc/[pid]/fd` 关联 socket inode 到 PID/FD/process name/uid/ppid/cmdline/exe/cwd/root/exe hash/dpkg package owner；权限失败进 error | container 关联依赖 container 模块，network owner 内暂不重复解释 | P0 | 增强 `entities/socket` owners |
| route/ARP | Done | `/proc/net/route`、`/proc/net/arp` 结构化 | 缺 IPv6 route、neighbor table、policy routing table all | P0/P1 | 增强 `facts/routes`、`facts/arp` |
| interface 基础 | Done | `/proc/net/dev` RX/TX、`if_inet6` IPv6、runtime IPv4/CIDR、sysfs MAC/MTU/flags/operstate/ifindex/master/kind hints | bridge/veth/tun/tap/wg/docker 语义后续可继续丰富 | P0 | 增强 `entities/interface` |
| hosts/resolv.conf | Done | 复制 legacy，并结构化 hosts、nameserver、search、options | systemd-resolved runtime 深挖后续补 | P0 | `facts/dns_config` |
| DHCP leases | LegacyOnly | `/var/lib/dhcp`、`/var/lib/dhclient` 复制 legacy | AI JSONL 未解析 lease IP、router、DNS、server、时间 | P1 | `facts/dhcp_leases` |
| proc net stats | LegacyOnly | `/proc/net/snmp`、`netstat`、`snmp6` legacy | AI JSONL 未结构化 counters | P2 | `facts/network_counters` |
| native network commands | LegacyOnly | `ifconfig/route/netstat/arp/ip addr/ip route/ip link/ip rule` legacy | AI JSONL 不依赖这些命令；可选解析用于交叉一致性 | P1 | `facts/network_command_observations` |
| conntrack | Done | `/proc/net/nf_conntrack`、`/proc/net/ip_conntrack`，NAT/reply tuple/state/timeout；缺失时输出 absent fact | 权限/内核模块不可用时只记录事实，不判断风险 | P0 | `facts/conntrack_entries` |
| nft/iptables | Done | `nft list ruleset`、`iptables-save`、`ip6tables-save` raw legacy + parser；缺失时输出 absent/errors | 复杂 nft rule 语义保持 rule text/token facts，不做策略解释 | P0 | `facts/firewall_rules` |
| DNS/runtime resolver | Missing/Partial | resolv.conf legacy | systemd-resolved、NetworkManager、dnsmasq、resolved runtime files未结构化 | P1 | `facts/dns_config` |
| proxy/tunnel config | Done | `http_proxy/https_proxy/all_proxy/no_proxy/ftp_proxy`、ssh ProxyCommand/ProxyJump、frp/ngrok/cloudflared/tailscale/wireguard/openvpn config 关键行；AI 输出脱敏凭据 | 不采集完整 tunnel secret；legacy/raw 仍保留原文复核 | P0 | `facts/network_persistence` |
| external flow enrichment | Done | socket 基础事实合并 process owner、cmdline、exe/cwd/root、exe hash、dpkg package、listener/outbound/local/remote flow_kind | 登录 session/container 深关联后续可扩展 | P0 | `facts/network_flows` |

## 建议实施顺序

1. Persistence A：systemd 深解析 + enabled symlink/drop-in
2. Persistence B：SSH authorized_keys/options + sshd_config 语义化
3. Persistence C：sudoers + shell profile + loader/PAM
4. Network A：interface enrichment + dns_config
5. Network B：socket owner enrichment，合并 process exe/cmdline/hash/package/container
6. Network C：conntrack + firewall/nft/iptables + proxy/tunnel config

## 本轮执行 Gate

本轮按用户要求由 subagent 执行 Dev / review / test 独立门禁。

Dev 拆分：

- Persistence Dev：只负责 `internal/collectors/persistence/*` 及对应测试，目标覆盖 Persistence A/B/C。
- Network Dev：只负责 `internal/collectors/network/*`、`internal/netproc/*` 及对应测试，目标覆盖 Network A/B/C。

主 agent 集成验收时必须确认：

- 新增 stream 仍进入单一 `ai/evidence.jsonl`，不得恢复模块级 JSONL 文件。
- 不出现 `risk`、`severity`、`verdict`、`malicious`、`suspicious` 等判断字段。
- 对已有 legacy/raw 产物只增不减。
- Parser fixture 覆盖关键样例：systemd drop-in/enabled、`~/.bash_profile`/`LD_PRELOAD`、authorized_keys options、sudoers NOPASSWD/SETENV、interface IPv4/MAC/MTU、resolv/hosts、conntrack/firewall。
- Ubuntu ARM64 VM 跑 `deep --scan none` 后抽样检查 JSONL 内容质量，而不仅是 JSON 可解析。

## 验收标准

- 每个新增能力必须进入单一 `ai/evidence.jsonl`，用 `stream` 区分，不新增模块 JSONL 文件。
- 只输出事实字段，不输出 risk/severity/verdict/suspicious/malicious。
- legacy/raw 只增不减；已有 ATTK 对齐产物不删除。
- fixture 单测覆盖 parser；Ubuntu ARM64 VM 跑 `deep --scan none` 后抽样检查内容质量。
