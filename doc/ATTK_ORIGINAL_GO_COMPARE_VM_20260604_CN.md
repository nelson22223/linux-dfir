# ATTK 原版 vs Go 重构版 VM 采集对比

生成时间：2026-06-04

## 范围

本次只比较信息采集能力，不比较病毒扫描、清理、文件恢复能力。

- 原版 ATTK：`attklnx.sh --accepteula -k`
- Go 重构版：`dfir-collector --profile deep --scan none`
- 测试主机：Ubuntu 24.04 ARM64 UTM VM
- 输出：
  - 原版：`/tmp/attk-original-run/attk_log/attk-2026.06.04.06.03.26`
  - Go 版：`/tmp/dfir-go-compare/out-deep-v2`

原版 ATTK 的 file scan 阶段在 ARM64 VM 上输出：

```text
Pattern is not ready. Section [File-based Scan] will be skipped.
```

本次比较排除 `filescan/`、`filerestore/`，只看采集产物。

## 运行结果

| 项目 | 结果 |
|---|---:|
| 原版 ATTK 退出码 | 0 |
| Go 重构版退出码 | 0 |
| 原版非扫描采集文件数 | 366 |
| Go legacy 非扫描采集文件数 | 1421 |
| Go AI stream 数 | 41 |
| 原版同名 legacy 覆盖 | 237 |
| 原版功能性结构化覆盖 | 129 |
| missing / partial | 0 |

## 关键 AI Stream

| Stream | 行数 |
|---|---:|
| `entities/host` | 1 |
| `entities/user` | 32 |
| `entities/group` | 58 |
| `entities/kernel_module` | 186 |
| `entities/process` | 129 |
| `entities/socket` | 134 |
| `entities/interface` | 2 |
| `entities/persistence_file` | 1459 |
| `entities/systemd_unit` | 1099 |
| `entities/package` | 734 |
| `entities/file` | 7215 |
| `facts/mounts` | 24 |
| `facts/mountinfo` | 24 |
| `facts/time` | 1 |
| `facts/routes` | 3 |
| `facts/arp` | 1 |
| `facts/cron_entries` | 22 |
| `facts/persistence_items` | 1086 |
| `facts/file_hashes` | 6805 |
| `facts/file_package_owners` | 114218 |
| `facts/log_events` | 11675 |
| `facts/auth_events` | 1 |
| `facts/audit_events` | 6087 |
| `entities/container` | 1 |

## 发现并修复的差异

初次对比发现一个兼容缺口：

```text
system/kernel/modprobe_-n-l-v.out
```

该文件是原版 ATTK 执行 `modprobe -n -l -v` 的 native command 输出。在当前 Ubuntu 24.04 上，该命令输出为：

```text
/sbin/modprobe: invalid option -- 'l'
```

虽然它只是旧参数的报错输出，按“只增不减”仍应保留。Go 版已补充：

- `legacy/system/kernel/modprobe_-n-l-v.out`
- `legacy/system/kernel/module/<module>.out`，对应原版 `modinfo <module>` 输出

补充后重新构建 ARM64、重跑 Go deep、重新对比，`missing_or_partial` 为 0。

## 覆盖结论

在 Ubuntu ARM64 VM 的非扫描采集范围内，Go 重构版满足“只增不减”：

- 原版 ATTK 同名 legacy 产物：已保留主要人工复核面。
- 原版 ATTK 命令文本产物：对于 `ps`、`lsof`、`netstat`、`ifconfig`、`route`、`arp`、`df`、`vmstat`、`uname`、`mounts`、`passwd/group/sudoers`、cron/rc/init 等已保留或增强。
- 原版 ATTK per-package/per-module 文本面：Go 版保留兼容文本或用更完整结构化事实覆盖。
- Go 版新增：systemd、SSH、shell profile、sudoers.d、browser raw DB copy、logs/audit/wtmp/btmp/lastlog、container namespace/cgroup、AI JSONL 单证据流。

## 后续仍建议补测

- x86_64 Linux VM 上跑同样对比，确认 `tmbrfix` 之外的 native command 输出差异。
- RHEL/Rocky/CentOS 上对比 rpm、secure/messages、systemd 路径差异。
- 有真实 Chrome/Firefox profile 的 Linux 用户环境。
- 有真实 Docker/containerd/Podman 的 Linux 环境。
