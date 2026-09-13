# DDEI Rootkit Detector（linux-dfir 定制分支）

分支 `ddei-rootkit-detector`：默认执行即 **libnet.so/xinetd LD_PRELOAD rootkit 家族检测**，
终端直接输出感染结论并在同目录留一份简单 log；随后按精简的 `ddei` profile 完成收集打包。
原有采集打包能力完整保留（`-profile deep|quick|standard` 照常可用）。

```
# 默认：检测 + 精简收集 + tar.gz 打包（结论写入进程退出码）
./dfir-collector

# 仅检测（秒级，无收集）
./dfir-collector -detect-only

# 恢复原始完整采集行为（跳过检测）
./dfir-collector -no-detect -profile deep
```

退出码：`0` CLEAN / `1` SUSPICIOUS / `2` LIKELY-INFECTED / `3` INFECTED。
检测 log：默认写到**可执行文件同目录** `ddei_rootkit_check_<时间戳>.log`（`-detector-log-dir` 可改），
收集模式下报告 JSON 同时进入证据包 `ai/ddei_rootkit/report.json`。

---

## 一、案例溯源分析（基于 dfir_20260912185443 证据包 + 样本逆向交叉）

### 1. 受害环境
- 主机 `O-BJC-A-COR-DDEI2`（Trend Micro DDEI 深度发现邮件检测仪专用设备）
- CentOS 7，kernel 3.10.0-693（2021-12 编译，长期未升级），ddei-system-3.2.0-1010
- 对外暴露 SMTP(25)/HTTPS(443)/SSH(22)，邮件过滤链（foxfilter/postfix/tika）直接接触不可信输入

### 2. 入侵时间线（ctime 还原，mtime 全部不可信——样本含 timestomp 功能且已实证使用）
| 时间(UTC) | 事件 | 依据 |
|---|---|---|
| **2026-08-06 02:36:44** | `multi-user.target.wants/xinetd.service` 符号链接建立（恶意 xinetd 持久化上线）★最早可溯痕迹 | symlink ctime |
| **2026-08-11 08:59:19** | `/etc/ld.so.preload` 写入，rootkit 全系统注入 | 文件 ctime |
| 2026-08-11 03:39（本地） | foxfilter 在 libspf2 中 segfault——与入侵窗口重合，疑为邮件侧触发 | messages |
| **2026-08-20 06:03:04** | `/usr/sbin/xinetd` 被替换/更新（运营中迭代版本） | 文件 ctime |
| 2026-09-10/11 起 | 日志反复出现 `ld.so: object '/usr/lib64/libnet.so' ... cannot be preloaded`（rootkit 文件短暂缺失窗口） | messages/journal |
| 2026-09-12 13:28（本地） | 重启后 systemd 报 `Unit not found`（unit 文件不可见），但恶意 xinetd(PPID=1) 仍由 DDEI 框架拉起 | journal + /proc |
| 2026-09-12 18:54（本地） | DFIR 采集 | manifest |

### 3. 入侵路径判定
保留日志无法直接定位初始入口（secure 日志仅存 2.5 小时、audit 无文件监控规则、journal 仅回溯至 9-10）。
间接证据全部指向**面向邮件处理栈的远程利用**而非凭据登录：
- 设备功能决定 25/443 长期接触不可信邮件流；DDEI 3.2/老内核存在多个已披露 RCE；
- 入侵窗口内 foxfilter(libspf2) 崩溃，符合恶意邮件触发解析漏洞的特征；
- 无 SSH 爆破/异常登录残留（2.5h 窗口内仅有管理网段 27.193.27.77 正常会话）；
- `/root/.ssh/authorized_keys` 为 2021 年产品安装自带，未被篡改。
（结论置信度：中。建议调取 8-6 前的防火墙/邮件网关上游日志复核 25/443 流量。）

### 4. 造成的后果
- **全系统用户态 rootkit**：`/usr/lib64/libnet.so`（364448B，=样本 libnet.so.1）经 ld.so.preload 注入
  systemd/auditd/journald 等全部动态链接进程，可按 PID 隐藏进程、按名隐藏文件（对取证工具隐身）；
- **RAT 常驻**：`/usr/sbin/xinetd` 被替换为 5.9MB Rust dropper（=样本 xinetd.1），由 DDEI 自身服务框架与
  systemd 双通道拉起，stdout 混入 DDEI 日志 imssctl.log；
- **内存驻留三级载荷**：dropper 内嵌 3.99MB 加密块（MD5("--world") 稀疏 XOR + gunzip → shellcode →
  尺寸派生密钥 XOR → 内存 ELF），进程含 RWX 区域运行完整任务框架（文件管理/上传下载/timestomp/
  shellcode 热加载/CONFIG_RELOAD）；
- **隐蔽性对抗**：时间戳伪造（xinetd mtime 拉回 2015）、反沙箱（检测 Cuckoo/FakeNet/Sysmon/chisel）、
  反复分析（zip 加密、字符串全加密、段头/重定位表破坏）；
- **横向潜力**：U 盘/挂载介质扫描（/media）+ 32/40/64-hex ID 互搜的传播协议；
- 该设备为**邮件安全网关**，全量企业邮件流经此处 → 邮件拦截/窃取风险。

### 5. C2 与网络 IOC
- **本构建无硬编码 C2 端点**（配置注入式：host/endpoint/port/secret/jitter 等字段运行时下发，
  本样本配置区为全零 = builder 交付态）；
- 出口 IP 探测（TLS，串行尝试）：`https://cip.cc` `https://ipinfo.io` `https://ifconfig.me`
  `https://myip.ipip.net` `https://icanhazip.com`；
- HTTP UA：`Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/108 ... Edg/108.0.1462.46`；
- Bot ID：`ec2d99096b958b06221c981d1e9262a3f84b9ccb9e6d496e9c3e11735383d73f`；
- 矿池标记探测：`/tmp/config.json` 含 `donate.v2.xmrig.com:3333` 时识别已有矿机；
- 文件 IOC：
  - `libnet.so.1`/`libnet.so` md5 `eebbba3f7ff5eb7ab0f64fc5074a6ce5`，sha256 `acf5641c...8dd27cc`
  - `xinetd.1`/`xinetd` md5 `003bf75d53504889e13bf12d6af5b28f`，sha256 `8c175c21...f21d763`（5974384B）
  - 内存层：payload_inner md5 `20b1e9f0e9baf4280d401e6739f06bda`；stage3.elf md5 `dce24bc47b5c02007052792f1516daa5`
  - 标记文件：`/root/sign.txt`、`/media/vbccsb`、`/home/vbccsb`
- 日志 IOC：`ld.so: object '/usr/lib64/libnet.so' from /etc/ld.so.preload cannot be preloaded`

---

## 二、有效证据点 ↔ 采集点映射（本案例实证）

| # | 证据点（本案例实证值） | 暴露什么 | 对应采集点（本工具 collector / artifact） | 检测器对应检查 |
|---|---|---|---|---|
| 1 | `/etc/ld.so.preload` 内容 `/usr/lib64/libnet.so` | rootkit 注入入口（一手证据） | persistence → `legacy/autorun/etc/ld.so.preload`、`persistence_items(ld_so_preload_entry)` | `preload_entry` (CONFIRMED) |
| 2 | `/proc/*/maps` 中 libnet.so 映射（systemd/auditd/journald 全部命中，364448B） | 注入范围 + 文件真实存在（绕过文件隐藏） | process → `lsof.out`/`procfs` maps、`ai/evidence.jsonl process.maps` | `proc_maps` (HIGH) |
| 3 | `/proc/2698/exe` → `/usr/sbin/xinetd` md5 `003bf75d...` | dropper 替换系统组件（哈希一手证据） | process → `open_files`/`file_hashes`（经 /proc fd 解析） | `xinetd_binary` (CONFIRMED) |
| 4 | xinetd maps 含 **RWX** 区域 | 内存载荷正在运行 | process → maps 统计 `writable_executable_count` | `proc_maps` (HIGH) |
| 5 | xinetd mtime=2015 vs ctime=2026-08-20 | timestomp 反取证实证 | files → `file_attributes`(ctime/mtime) | `xinetd_binary` (MEDIUM) |
| 6 | wants 符号链接 ctime=2026-08-06 | 持久化建立时间（最早可溯时间点） | persistence → systemd_unit/`file_attributes` | `systemd_unit` (MEDIUM) |
| 7 | messages/journal `cannot be preloaded` 报错 | rootkit 文件缺失窗口/存在性旁证 | logs → `var_log_messages*`/`journalctl_json.out` | `log_traces` (MEDIUM) |
| 8 | `/usr/lib64/libnet.so` 文件本体 + 哈希 | 家族精确认定 | files 扫描范围需覆盖 /usr/lib64（本案哈希清单**漏掉此文件**——教训） | `libnet_file` (CONFIRMED/HIGH) |
| 9 | `/root/sign.txt`、`/media/vbccsb` | 感染标记 | files/enum 扫描（本案未覆盖 /root /media——教训） | `marker_file` (CONFIRMED) |
| 10 | 进程环境变量继承 DDEI 产品变量、stdout→imssctl.log | 伪装/拉起方式溯源 | process → environ/fds | （溯源用，不做检查） |

**取证教训（本工具已吸收）**：
- LD_PRELOAD rootkit 对**动态链接取证工具**完全不可信，本检测器为**纯静态 Go 二进制**（不经 libc，
  preload 钩子无效）；`/proc/*/maps`、`/proc/*/exe` 是不可隐藏的锚点；
- 文件枚举范围必须包含 `/usr/lib64`、`/root`、`/media`（本案 quick 扫描缺失导致 8/9 两点遗漏）；
- 一切 mtime 不可信，ctime 才是时间线依据。

---

## 三、实现说明

- 检测器：`internal/detector/ddeirootkit/`（纯标准库、只读、无依赖；`Options.Root` 可指向 fixture 便于测试）
- 集成：`internal/app/app.go` —— 默认先跑检测（终端结论 + 同目录 log + 退出码），
  再按 `profiles/ddei.yaml`（host/system/process/network/persistence/logs，10 分钟上限）收集打包；
  报告 JSON 随证据包归档（`ai/ddei_rootkit/report.json`）。
- 判定规则：任一 CONFIRMED → INFECTED；≥2 HIGH → LIKELY-INFECTED；1 HIGH 或 ≥2 MEDIUM → SUSPICIOUS；否则 CLEAN。
- 测试：`go test ./internal/detector/ddeirootkit/`（fixture 覆盖 clean/感染/弱指标/日志痕迹/log 落盘）。
- 构建：`GOOS=linux GOARCH=amd64 go build -o dfir-collector ./cmd/dfir-collector`（CGO_ENABLED=0 静态）。
