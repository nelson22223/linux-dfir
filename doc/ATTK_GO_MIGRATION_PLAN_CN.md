# ATTK Linux DFIR Go 迁移与进化计划

生成时间：2026-06-02

## 0. 结论

原始 ATTK for Linux 的外层能力本质是一个 Bash 应急采集编排器，复杂扫描能力来自内嵌的 `tmbrfix` 二进制。若不重构扫描引擎，只将其作为可选插件调用，那么迁移到 Go 的工作量是可控的中等规模项目。

建议目标不是逐行翻译 Bash，而是迁移其采集面，并升级为：

- 一次性运行的 Linux DFIR 采集器。
- 默认只采集，不清理，不杀进程，不修改业务文件。
- 对抗目标机命令被替换或缺失的问题。
- 输出 AI agent 友好的结构化证据包。
- 可选调用原始 `tmbrfix`、YARA、osquery 等外部扫描/查询组件。

推荐定位：

```text
AI-ready Linux Incident Collection Toolkit
```

## 1. 原始 ATTK 能力与实现方式梳理

### 1.1 程序形态

| 项目 | 原始实现 |
|---|---|
| 主程序 | `attklnx.sh` Bash 脚本 |
| 配置 | `attk.cfg`，用于追加文件扫描目标 |
| EULA | `eula.txt` |
| 内嵌扫描器 | `tmbrfix`，由脚本从自身 payload 中释放 |
| 输出目录 | `attk_log/attk-<时间>/` |
| 输出归档 | `attk_log/attk-<时间>.tar.gz` |
| 运行要求 | root 用户，Linux 系统 |

本地证据：

- 参数与版本定义：`attklnx.sh:1-28`
- root/Linux 检查：`attklnx.sh:946-954`
- 主流程：`attklnx.sh:1030-1054`
- payload 释放：`attklnx.sh:897-904`

### 1.2 命令发现模块

函数：`FindCmd`、`FindAllCmds`

原始能力：

- 使用 `which` 查找系统命令。
- 将缺失命令写入 `command_not_found.out`。
- 后续模块依赖这些命令路径变量执行采集。

涉及命令：

```text
awk cat chmod column cp cut date file find grep ls md5sum mkdir mv rm sed
sha1sum sort sqlite3 tail tar zdump hostid hostname stat vmstat who
lsmod modinfo modprobe uname df fdisk blkid swapon lsof ps at crontab
ifconfig ip netstat route arp apt-cache dpkg rpm
```

本地证据：`attklnx.sh:97-196`

局限：

- 完全信任目标机上的 `which` 和被找到的命令。
- 如果命令被替换、hook、alias 污染或行为异常，采集结果也会被污染。
- 缺失命令只记录，不做更强 fallback。

### 1.3 系统摘要模块

函数：`SystemSummary`

原始能力：

- 主机名、hostid、架构、内核版本。
- `/proc/meminfo` 内存摘要。
- `/etc/*-release` 发行版信息。
- `vmstat`、`swapon`、`df`、`ifconfig` 或 `ip addr` 输出。
- 写入 `SUMMARY`。

本地证据：`attklnx.sh:199-258`

局限：

- 字段是文本拼接，后续自动分析需要二次解析。
- `uname`、`vmstat`、`df` 等命令结果可信度依赖目标系统。

### 1.4 系统、内核、用户、磁盘、时间模块

函数：`SystemInfo`、`KernelInfo`、`UserInfo`、`DiskInfo`、`TimeInfo`

原始能力：

| 子模块 | 采集内容 | 本地证据 |
|---|---|---|
| KernelInfo | `lsmod`、每个模块的 `modinfo`、`modprobe -n -l -v` | `attklnx.sh:262-305` |
| UserInfo | `who -a`、复制 `/etc/passwd`、`/etc/sudoers`、`/etc/group` | `attklnx.sh:308-331` |
| DiskInfo | `df -ak`、`/proc/mounts`、`fdisk -l`、`blkid` | `attklnx.sh:334-366` |
| TimeInfo | `zdump /etc/localtime`、`zdump /usr/share/zoneinfo/*` | `attklnx.sh:369-386` |
| SystemInfo | `uname -a`、`vmstat -s`、SSH host key stat，然后调用上述子模块 | `attklnx.sh:389-422` |

局限：

- 没有 systemd 单元、journal、auditd、container runtime、cgroup、namespace 现代 Linux 信息。
- 大量依赖外部命令。
- 复制 `/etc/sudoers` 但没有权限策略解析。

### 1.5 进程模块

函数：`ProcessInfo`

原始能力：

- `ps auxw`
- `ps -elf`
- `jobs -l`
- `lsof`

本地证据：`attklnx.sh:425-452`

局限：

- `ps` 和 `lsof` 都依赖目标机命令。
- 未直接读取 `/proc/[pid]/cmdline`、`exe`、`cwd`、`status`、`maps`、`environ`。
- 没有 socket inode 到 PID 的结构化关联。
- `lsof` 缺失时，打开文件视角基本丢失。

### 1.6 自启动/持久化模块

函数：`AutorunInfo`

原始能力：

- 复制 `/etc/at.allow`、`/etc/at.deny`、`/etc/inittab`。
- 复制 `/etc/cron*`、`/etc/rc*`。
- 复制 `/var/spool/cron/crontabs`、`/var/spool/cron`、`/var/cron/tabs`、`/var/spool/at`、`/var/at/jobs`、`/etc/init`、`/etc/init.d`。
- 复制 `/var/log/cron`。

本地证据：`attklnx.sh:455-494`

局限：

- 不覆盖或不完整覆盖 systemd：
  - `/etc/systemd/system`
  - `/usr/lib/systemd/system`
  - `/lib/systemd/system`
  - user units
  - timers
- 不覆盖常见 shell/profile 持久化：
  - `/etc/profile`
  - `/etc/profile.d`
  - `~/.bashrc`
  - `~/.bash_profile`
  - `~/.ssh/authorized_keys`
- 不做结构化解析和风险归类。

### 1.7 网络模块

函数：`NetworkInfo`

原始能力：

- `ifconfig -a`
- `route -nv`
- `netstat -avpeW`
- `netstat -rn`
- `netstat -s`
- `arp -a`
- `ip addr`
- `ip route`
- `ip link`
- `ip rule`
- 复制 `/etc/hosts`
- 复制 `/var/lib/dhcp`、`/var/lib/dhclient`

本地证据：`attklnx.sh:497-546`

局限：

- 依赖 net-tools/iproute2 系统命令。
- 没有直接解析 `/proc/net/tcp`、`udp`、`unix`。
- 没有将连接结构化为 PID、进程、socket、远端地址、监听状态。
- 没有采集 DNS 配置、NetworkManager、systemd-resolved、iptables/nftables。

### 1.8 浏览器历史模块

函数：`ChromeInfo`、`FirefoxInfo`、`BrowserInfo`

原始能力：

- 依赖 `sqlite3`。
- 导出 Chrome 历史：`/home/*/.config/google-chrome/Default/History`
- 导出 Firefox 历史：`/home/*/.mozilla/firefox/*.default/places.sqlite`
- 输出访问时间和 URL。

本地证据：

- Chrome：`attklnx.sh:549-570`
- Firefox：`attklnx.sh:573-594`

局限：

- 仅覆盖特定默认 profile 路径。
- 依赖目标机 `sqlite3`。
- 没有复制原始 SQLite DB 与解析结果并存。
- 没有脱敏策略。

### 1.9 文件枚举与元数据模块

函数：`EnumInfo`

原始能力：

- 枚举内核模块文件。
- 用 `lsof -Fn` 枚举进程打开文件。
- 从 cron 文件中提取 autorun 命令并用 `which` 定位。
- 枚举浏览器插件目录。
- 对枚举文件采集：
  - `stat`
  - SHA1
  - MD5
  - `file` 类型
  - RPM/DPKG 包归属
- 对归属包采集：
  - `apt-cache show`
  - `/usr/share/doc/<pkg>/copyright`
  - `rpm -qi`

本地证据：`attklnx.sh:604-753`

局限：

- 枚举面窄，偏 2016 年 Linux 环境。
- 大量依赖 `lsof`、`stat`、`file`、`sha1sum`、`md5sum`、`rpm`、`dpkg`。
- 大文件超过 100MB 跳过哈希。
- 无统一 JSON schema。
- 没有文件时间线、最近变更、SUID/SGID、world-writable、webroot、tmp 可疑路径等现代应急常用视角。

### 1.10 扫描/清理/恢复模块

函数：`ScanInfo`、`FilescanInfo`、`FileRestoreInfo`

原始能力：

- 从脚本尾部释放 payload。
- payload 中包含 `tmbrfix`。
- 对 `attk.cfg` 和枚举结果中的目标进行扫描。
- 默认使用 `-LQD` 输出隔离清单。
- 加 `-c` 时使用 `-C+` 清理。
- 加 `-r <dir>` 时恢复隔离文件。

本地证据：

- 目标构造：`attklnx.sh:756-782`
- pattern 检查：`attklnx.sh:811-820`
- 扫描调用：`attklnx.sh:823-837`
- 恢复调用：`attklnx.sh:840-895`
- payload 释放：`attklnx.sh:897-904`

本次迁移策略：

- 不重构 VSAPI/tmbrfix。
- 将其作为可选扫描插件。
- 默认禁用清理，清理必须显式开启并二次确认。
- Go 主程序即使扫描器不可用，也应完成采集。

### 1.11 归档模块

函数：`ArchiveInfo`

原始能力：

- 在 `LOGDIR` 下执行 `tar czf`。
- 输出归档 MD5/SHA1。
- 默认删除未归档的 session 目录，`-k` 保留。

本地证据：`attklnx.sh:913-938`、`attklnx.sh:1056-1059`

局限：

- 归档内缺少 manifest。
- 只给整个包 MD5/SHA1，没有每个 artifact 的 hash、采集错误、来源可信度、parser 版本。
- 无加密、压缩算法选择、分卷、大文件策略。

## 2. Go 实现计划与原版对比

### 2.1 总体架构

建议 Go 项目结构：

```text
linux-dfir/
  cmd/dfir-collector/
  internal/
    app/
    artifact/
    evidence/
    collectors/
      host/
      system/
      kernel/
      users/
      process/
      network/
      persistence/
      browser/
      files/
      packages/
      logs/
      container/
    scanners/
      tmbrfix/
      yara/
      osquery/
    parsers/
    archive/
    trust/
  profiles/
    quick.yaml
    standard.yaml
    deep.yaml
  schemas/
```

运行形态：

```text
dfir-collector-linux-amd64
dfir-collector-linux-arm64
dfir-collector-linux-386
```

建议参数：

```text
--profile quick|standard|deep
--output <dir>
--case-id <id>
--keep-workdir
--scan tmbrfix|yara|none
--clean disabled|confirm|force
--max-file-size
--timeout
--encrypt
--redact
--output-mode legacy|ai|dual
```

### 2.2 输出模型

建议采用双轨输出，默认 `dual`：

1. `legacy/`：尽量保持原始 ATTK 的目录和文件命名，便于人工复核、历史流程兼容、迁移前后对比。
2. `ai/`：面向 AI agent 的结构化 JSONL/JSON 输出，便于自动关联、时间线分析和报告生成。

推荐目录结构：

```text
attk_log/
  attk-<时间>/
    legacy/
      SUMMARY
      system/
      process/
      autorun/
      network/
      browser/
      enum/
      filescan/
      filerestore/
      command_not_found.out
    ai/
      manifest.json
      collection_log.jsonl
      host_profile.jsonl
      artifact_index.json
      entities.jsonl
      timeline.jsonl
      findings_candidates.jsonl
      errors.jsonl
      raw/
      parsed/
      normalized/
```

`legacy/` 目标：

- 尽量复刻 ATTK 原始输出结构和 `.out` 文本文件。
- 保留人工分析习惯。
- 便于验证 Go 版是否覆盖原始能力。
- 对原始 `tmbrfix` 输出保持兼容。

`ai/` 目标：

- 每个采集项都有结构化记录。
- 每条记录保留来源、采集时间、可信度、parser 版本、原始证据路径。
- 便于 AI agent 做实体关联、时间线重建、异常归纳和报告生成。

建议每个采集项在 `ai/` 中保留三层：

```text
raw/          原始证据
parsed/       解析后 JSONL
normalized/   标准化实体、事件、时间线
```

`ai/` 核心文件：

```text
manifest.json
collection_log.jsonl
host_profile.jsonl
artifact_index.json
entities.jsonl
timeline.jsonl
findings_candidates.jsonl
errors.jsonl
```

每条记录建议统一 schema：

```json
{
  "artifact": "linux.process.procfs",
  "host_id": "host-...",
  "case_id": "case-...",
  "collected_at": "2026-06-02T10:00:00+08:00",
  "source_type": "procfs",
  "source_path": "/proc/1234/status",
  "collector": "process/v1",
  "parser": "proc_status/v1",
  "trust": "collector_direct",
  "data": {}
}
```

可信度建议：

| trust | 含义 |
|---|---|
| `collector_direct` | Go 程序直接读取 `/proc`、`/sys`、文件系统 |
| `bundled_tool` | 自带 BusyBox/osquery/tmbrfix 输出 |
| `native_command` | 目标机原生命令输出 |
| `copied_file` | 复制的原始文件 |
| `derived` | 后处理推导结果 |

### 2.3 模块迁移计划

| ATTK 模块 | 原始实现 | Go 迁移计划 | Go 版优势 | Go 版劣势/风险 |
|---|---|---|---|---|
| 命令发现 | `which` 查命令 | 改为 capability registry：Go direct、bundled tool、native fallback 三层 | 不再把系统命令作为默认可信来源；缺失能力可明确记录 | 实现复杂度增加 |
| 系统摘要 | 拼接命令输出 | 直接读 `/etc/os-release`、`/proc/meminfo`、`/proc/cpuinfo`、`uname` syscall/库 | 结构化、字段稳定、AI 易消费 | 部分发行版字段差异需兼容 |
| Kernel | `lsmod`、`modinfo`、`modprobe` | 解析 `/proc/modules`，复制模块路径，fallback 调用 `modinfo` 或 BusyBox | 避免依赖 `lsmod`；可输出 module entity | `modinfo` 的 rich metadata 直接解析成本高 |
| User | 复制 passwd/group/sudoers，`who -a` | 复制原始文件 + 解析 users/groups/sudoers；采集 lastlog/wtmp 可选 | 可直接判断 root 权限账号、异常 shell、sudo 权限 | wtmp/lastlog 二进制解析需要实现或调用库 |
| Disk | `df`、`/proc/mounts`、`fdisk`、`blkid` | 解析 `/proc/mounts`、`/proc/self/mountinfo`、`/sys/block`；fallback `blkid` | 容器/namespace 视角更清楚 | 分区表深度解析可后置 |
| Time | `zdump` | 读取 `/etc/localtime` 指向、采集 timezone 文件元数据，fallback `zdump` | 输出统一时区上下文 | 不需要一开始完整枚举所有 zoneinfo |
| Process | `ps`、`lsof` | 直接读 `/proc/[pid]/{status,cmdline,environ,exe,cwd,maps,fd}` | 抗命令替换，能关联 exe/cwd/fd/socket inode | 权限不足、进程消失需要健壮处理 |
| Autorun | 复制 cron/rc/init | 扩展为 persistence collector：cron、systemd units/timers、rc、init、shell profile、ssh authorized_keys | 更贴近现代 Linux 入侵手法 | 路径广，需 profile 控制体积 |
| Network | `ifconfig`、`netstat`、`ip`、`arp` | 解析 `/proc/net/*`，netlink 获取接口/路由，socket inode 关联进程，fallback BusyBox/native | 结构化连接表，抗命令替换 | netlink 实现比调用命令复杂 |
| Browser | `sqlite3` 查询固定路径 | profile discovery + 复制原始 DB + 只读 SQLite 解析；支持 Chrome/Chromium/Firefox 多 profile | 原始证据与解析结果并存；可脱敏 | SQLite CGO/纯 Go 方案需选型 |
| Enum | `lsof`、cron、browser plugin、hash/package | 扩展为 file artifact collector：modules、open files、persistence targets、SUID、recent files、tmp/webroot、hash、file type | 文件视角更完整，可输出时间线 | 深度扫描可能慢，需要限速/上限 |
| Package | `rpm/dpkg/apt-cache` | 第一阶段调用 native 命令并标记 `native_command`；第二阶段解析 rpmdb/dpkg status | 保持兼容，逐步提升可信度 | 直接解析包数据库工作量中等 |
| Scanner | 释放并执行 `tmbrfix` | scanner plugin：校验 hash、检查架构、超时、隔离输出、解析 log | 不影响主采集；可替换 YARA/osquery | `tmbrfix` 仍只适合 x86/i386 兼容 Linux |
| Archive | `tar.gz` | tar.zst/zip + manifest + 每项 hash + 可选加密 | 证据链完整，便于 AI agent 读取 | 加密/压缩/分卷要处理运维体验 |

### 2.4 阶段计划

#### 阶段 0：基线复刻

目标：完整复刻 ATTK 外层采集面，不追求新增能力。

交付：

- CLI。
- 输出目录结构。
- 系统、用户、磁盘、进程、网络、自启动、浏览器、枚举、归档。
- `tmbrfix` 可选调用，但默认关闭。

预计：1-2 周。

#### 阶段 1：AI-ready MVP

目标：在保留原始 ATTK 风格输出的同时，增加结构化证据输出。默认双轨输出：

- `legacy/`：原始 ATTK 风格目录和 `.out` 文件。
- `ai/`：JSONL/JSON 结构化证据。

交付：

- `legacy/SUMMARY`
- `legacy/system/`
- `legacy/process/`
- `legacy/autorun/`
- `legacy/network/`
- `legacy/browser/`
- `legacy/enum/`
- `manifest.json`
- `collection_log.jsonl`
- `host_profile.jsonl`
- `processes.jsonl`
- `network_connections.jsonl`
- `persistence.jsonl`
- `users.jsonl`
- `files.jsonl`
- `packages.jsonl`
- `timeline.jsonl`
- 原始证据 `raw/`

预计：3-5 周。

#### 阶段 2：实战增强

目标：解决目标机命令被替换、感染后环境不可信的问题。

交付：

- 自带 BusyBox 兜底。
- Go 直接解析 `/proc`、`/sys`、关键配置。
- native command 输出降级为低可信来源。
- 多源交叉验证。
- profile 控制采集深度。
- 文件大小、路径、超时、错误统一治理。

预计：6-10 周。

#### 阶段 3：企业级增强

目标：让工具可稳定用于客户现场应急。

交付：

- amd64/arm64/386 多架构。
- 可选 osquery/yara/tmbrfix 插件。
- 证据包加密。
- 离线规则包。
- 脱敏策略。
- AI agent ingest schema。
- 报告模板与自动 triage prompt。

预计：2-3 个月。

## 3. 原版基础上的可进化方向

### 3.1 从命令输出转向直接采集

原版问题：

- `ps`、`netstat`、`lsof`、`find`、`tar`、`md5sum` 等命令一旦被替换，结果不可信。

进化方向：

- 进程：直接读 `/proc/[pid]`。
- 网络：直接读 `/proc/net/*` 或 netlink。
- 模块：直接读 `/proc/modules`、`/sys/module`。
- 文件：Go 原生 walk、stat、hash。
- 打包：Go 原生 archive。
- 命令输出只作为补充证据。

### 3.2 自带 BusyBox，但只作为 fallback

BusyBox 适合作为“可信基础工具箱”，因为它是一个多调用二进制，提供常用 Unix 工具集合，且可以静态编译。参考来源：

- BusyBox official site: https://busybox.net/
- BusyBox FAQ: https://busybox.net/FAQ.html

但 BusyBox 不应成为主采集实现，因为：

- applet 能力弱于 GNU 工具。
- 不包含 `lsof`、`sqlite3`、`journalctl`、`rpm`、`dpkg`。
- 无法绕过内核级 rootkit。

推荐策略：

```text
Go direct > bundled BusyBox/osquery > native command
```

### 3.3 引入 artifact profile

参考 UAC 和 Velociraptor 的思想：

- UAC 是面向 Unix-like 系统的一次性 artifacts collector，适合学习 profile 化采集与离线打包。
- Velociraptor Offline Collector 支持离线采集包、artifact 定义、加密和后续导入分析，适合学习“离线采集 + 中心化分析”的模型。

参考来源：

- UAC: https://github.com/tclahr/uac
- Velociraptor Offline Collections: https://docs.velociraptor.app/docs/deployment/offline_collections/
- Velociraptor Collector CLI: https://docs.velociraptor.app/docs/cli/collector/

建议 profile：

| Profile | 用途 |
|---|---|
| `quick` | 5-10 分钟内完成，适合初筛 |
| `standard` | 默认应急采集，覆盖主机、进程、网络、持久化、日志 |
| `deep` | 深度文件枚举、日志、容器、浏览器、包、hash |
| `minimal-safe` | 高敏客户环境，只采集低敏元数据 |

### 3.4 引入 osquery 作为可选结构化查询组件

osquery 将系统状态暴露为 SQL 查询接口，官方定位是以 SQL 查询方式获取系统可见性。参考来源：

- osquery official site: https://osquery.io/
- osquery GitHub: https://github.com/osquery/osquery
- osquery schema: https://osquery.io/schema/

适合能力：

- 进程、用户、包、内核模块、监听端口、文件哈希、启动项等结构化查询。

注意：

- osquery 不替代完整 DFIR 采集器。
- 不适合直接负责原始证据复制、证据链、归档、AI schema。
- 建议作为可选 plugin，而不是核心依赖。

### 3.5 面向 AI agent 的证据包

原版 ATTK 输出主要是 `.out` 文本，适合人读，不适合 AI 稳定分析。Go 版不应删除这类输出，而应采用双轨输出：

- `legacy/` 保留原始 ATTK 风格输出，作为人工复核和迁移对照。
- `ai/` 新增结构化 JSONL/JSON 输出，作为 AI agent 的主输入。

进化方向：

```text
legacy/
  SUMMARY
  system/
  process/
  autorun/
  network/
  browser/
  enum/
ai/
  raw/
    原始证据
  parsed/
    单项解析 JSONL
  normalized/
    标准化实体、事件、时间线
  manifest.json
  artifact_index.json
  collection_log.jsonl
  timeline.jsonl
  findings_candidates.jsonl
```

AI agent 输入重点：

| 文件 | 用途 |
|---|---|
| `manifest.json` | 知道采集了什么、缺了什么、每项 hash |
| `host_profile.jsonl` | 建立主机上下文 |
| `collection_log.jsonl` | 判断采集可信度和失败点 |
| `entities.jsonl` | 主体：进程、用户、文件、连接、服务、包 |
| `timeline.jsonl` | 还原攻击时间线 |
| `findings_candidates.jsonl` | 采集器给出的候选异常，不直接下结论 |
| `raw/` | AI 或人工复核证据 |

建议 AI 分析策略：

- 采集器只做事实、弱规则和候选异常。
- AI agent 负责关联、排序、研判、生成报告。
- 所有 AI 结论必须引用 artifact id 和 source path。

### 3.6 现代 Linux 能力补齐

原版 ATTK 缺少的关键现代采集面：

| 方向 | 建议采集 |
|---|---|
| systemd | unit、timer、service override、user units |
| journal | `journalctl --output=json` fallback，或复制 journal 文件 |
| auditd | `/var/log/audit/audit.log`、audit rules |
| containers | Docker/containerd/kubelet 配置、容器进程、mount namespace |
| cgroup | cgroup v1/v2、进程归属 |
| SSH | `authorized_keys`、known_hosts、sshd_config |
| Shell history | bash/zsh/fish history，带脱敏 |
| Webroot/tmp | `/tmp`、`/var/tmp`、`/dev/shm`、常见 webroot |
| SUID/SGID | 权限异常、最近变更 |
| PAM | `/etc/pam.d`、`ld.so.preload`、profile hooks |
| DNS/proxy | resolv.conf、systemd-resolved、NetworkManager |
| Firewall | iptables、nftables、firewalld、ufw |

### 3.7 扫描能力插件化

建议扫描器作为插件，不进入采集主链路：

```text
scanners/
  tmbrfix
  yara
  osquery
  clamav
  ioc_matcher
```

`tmbrfix` 插件策略：

- 检查系统为 Linux。
- 检查 CPU/可执行兼容性：i386 或 amd64 且支持 32 位 ELF。
- 校验内置二进制 hash。
- 默认 scan-only。
- `clean` 必须显式启用。
- 所有 stdout/stderr/log/exit code 进入 scanner evidence。

### 3.8 证据可信与抗污染

建议每个 artifact 记录：

```json
{
  "source": "procfs",
  "collector_method": "direct_read",
  "trust": "collector_direct",
  "raw_sha256": "...",
  "parser_version": "v1",
  "errors": []
}
```

交叉验证例子：

| 事实 | 可信源 | 交叉源 |
|---|---|---|
| 进程列表 | `/proc/[pid]` direct | BusyBox `ps`、native `ps` |
| 网络连接 | `/proc/net/*` + fd inode | BusyBox/native `netstat` |
| 模块 | `/proc/modules` | `modinfo`、module file hash |
| 包归属 | rpmdb/dpkg status | native `rpm/dpkg` |

### 3.9 安全与合规

默认安全策略：

- 默认不清理、不删除、不 kill。
- 不上传外网。
- 输出包本地生成。
- 可选加密。
- 敏感数据分级：
  - `public_summary`
  - `restricted_evidence`
  - `sensitive_raw`
- 浏览器历史、shell history、环境变量、authorized_keys 应标记敏感。

## 4. 推荐实施顺序

### 4.1 第一批必须实现

1. CLI 与 profile。
2. 输出目录、manifest、collection log。
3. host/system/users/disk/time。
4. process direct `/proc`。
5. network direct `/proc/net`。
6. persistence：cron、systemd、ssh、profile。
7. files：枚举、stat、hash、file category。
8. archive。

### 4.2 第二批增强

1. BusyBox fallback。
2. Browser DB 复制和解析。
3. package inventory。
4. logs/journal/audit。
5. container/cgroup。
6. timeline normalization。
7. AI ingest schema。

### 4.3 第三批插件

1. `tmbrfix` plugin。
2. YARA plugin。
3. osquery plugin。
4. IOC matcher。
5. 证据包加密。

## 5. 工作量评估

| 阶段 | 内容 | 粗估 |
|---|---|---|
| PoC | ATTK 采集面复刻 + tar 输出 | 1-2 周 |
| MVP | Go direct collectors + JSONL/manifest + 基础归档 | 3-5 周 |
| 实战版 | BusyBox fallback、profile、超时、错误、AI schema | 6-10 周 |
| 企业版 | 多架构、插件、加密、规则、完整 QA | 2-3 个月 |

关键风险：

- 浏览器 SQLite 解析是否引入 CGO。
- 包数据库直接解析复杂度。
- `/proc` 采集时进程消失、权限不足、容器视角差异。
- 大文件哈希和日志采集的性能/体积控制。
- `tmbrfix` 兼容性和法律授权边界。

## 6. 最终建议

不要做“Go 版 ATTK 复刻品”，而要做“ATTK 采集面升级版”：

```text
ATTK Bash 采集面
+ Go direct collectors
+ BusyBox fallback
+ artifact profiles
+ structured evidence
+ AI-ready timeline/entities
+ optional scanner plugins
```

这样可以保留 ATTK 的轻量一次性应急优势，同时解决原版最明显的问题：

- 系统命令不可信。
- 输出不结构化。
- 现代 Linux 覆盖不足。
- 不适合 AI agent 后续分析。
