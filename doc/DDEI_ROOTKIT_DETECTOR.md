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

## 三、检测逻辑 v2（简化 + 行为判别）

### 设计目标
回答唯一问题：**这台主机是否被该家族攻陷**。检查从 7 组砍到 4 组，每组独立决定性（任一命中即 INFECTED），
判定从 4 级简化为 3 态（CLEAN / REVIEW / INFECTED，退出码 0/1/3）。

### 误报/漏报治理（v1 → v2）

| v1 检查 | 误报风险 | v2 处置 |
|---|---|---|
| 未知哈希的 libnet.so → HIGH | **真实误报**：`libnet-devel` 包合法提供 /usr/lib64/libnet.so（发包库，导出 libnet_* 符号） | 改为**行为判别**：库必须 DEFINE ≥2 个 libc 文件遍历符号（stat/readdir/open/unlink 族）才算 hook 库——合法库只会 import 不会 export 这些符号；经真实样本验证 libnet.so.1 导出 17 个符号中 16 个为 hook 符号 |
| 任意非白名单 preload 条目 → HIGH | 设备/产品可能合法使用 ld.so.preload | 降级为 REVIEW（软信号，不参与定性） |
| sign.txt 存在即 CONFIRMED | 管理员可能自建同名文件 | 必须**内容为 64-hex bot id** 才定性 |
| systemd unit / 日志痕迹 → MEDIUM | DDEI 正常也启用 xinetd.service；preload 损坏条目也产生同样报错 | 从检测器中**移除**（采集阶段仍收集这些证据供人工分析） |
| 仅按名字找 libnet.so | **真实漏报**：家族换名（如 libkrb5.so 样式）即漏 | preload 条目**逐个按行为判别**（名字无关）；/proc maps 中映射的 .so 同样按符号验证 |
| 仅按哈希定性 | **真实漏报**：攻击者在运营中迭代（本案 8-20 就更新过二进制），重建即换哈希 | 哈希 + 静态无 PT_INTERP + hook 符号集三重行为锚点，抗重建 |

### 4 组决定性检查
1. **preload_hooklib**：/etc/ld.so.preload 每个条目 → 目标文件按（家族哈希 ∨ DEFINE≥2 个 hook 符号）判别 → COMPROMISED；文件缺失或非 hook → REVIEW
2. **xinetd_replaced**：/usr/sbin/xinetd 为（家族哈希 ∨ 静态无 PT_INTERP ∨ >1MB）→ COMPROMISED（原版 xinetd 为 ~166KB 动态链接）
3. **live_behavior**：任一进程映射了 hook 库（按符号验证，非按名）∨ xinetd 进程存在 RWX 内存区 → COMPROMISED（/proc 由内核提供，用户态 rootkit 对静态二进制不可藏）
4. **markers**：/root/sign.txt 内容为 64-hex ∨ /media/vbccsb、/home/vbccsb 存在 → COMPROMISED

判定：任一 COMPROMISED → **INFECTED**；仅软信号 → **REVIEW**；无 → **CLEAN**。

### 可信性设计
- 检测器为纯静态 Go 二进制（CGO_ENABLED=0），不加载 libc → LD_PRELOAD 钩子无效；
- /proc/*/maps、/proc/*/exe 为内核数据源；
- 符号判别用标准库 debug/elf，版本无关实现（PT_INTERP 手动解析、导出以符号值非零判定）。

## 四、实现说明

- 检测器：`internal/detector/ddeirootkit/`（纯标准库、只读、无依赖；`Options.Root` 可指向 fixture 便于测试）
- 集成：`internal/app/app.go` —— 默认先跑检测（终端结论 + 同目录 log + 退出码），
  再按 `profiles/ddei.yaml`（host/system/process/network/persistence/logs，10 分钟上限）收集打包；
  报告 JSON 随证据包归档（`ai/ddei_rootkit/report.json`）。
- 判定规则：任一 CONFIRMED → INFECTED；≥2 HIGH → LIKELY-INFECTED；1 HIGH 或 ≥2 MEDIUM → SUSPICIOUS；否则 CLEAN。
- 测试：`go test ./internal/detector/ddeirootkit/`（fixture 覆盖 clean/感染/弱指标/日志痕迹/log 落盘）。
- 构建：`GOOS=linux GOARCH=amd64 go build -o dfir-collector ./cmd/dfir-collector`（CGO_ENABLED=0 静态）。
