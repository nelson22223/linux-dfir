# Phase 14 E2E 验收清单

更新时间：2026-06-02

## macOS 已完成验收

开发机：macOS arm64。以下验证证明工程、输出、JSON/JSONL、归档和 unsupported 路径可用；不代表真实 Linux 成功路径已证明。

```sh
go test ./...
make linux

go run ./cmd/dfir-collector --profile quick --output /tmp/dfir-e2e-quick --output-mode dual --case-id e2e-quick --timeout 5m
go run ./cmd/dfir-collector --profile standard --output /tmp/dfir-e2e-standard --output-mode dual --case-id e2e-standard --timeout 15m
go run ./cmd/dfir-collector --profile deep --output /tmp/dfir-e2e-deep --output-mode dual --case-id e2e-deep --timeout 45m --archive
go run ./cmd/dfir-collector --profile minimal-safe --output /tmp/dfir-e2e-minimal --output-mode dual --case-id e2e-minimal --timeout 5m
go run ./cmd/dfir-collector --profile minimal-safe --scan tmbrfix --output /tmp/dfir-e2e-scanner --output-mode dual --case-id e2e-scanner --timeout 5m
```

结果摘要：

| Profile | Artifacts | JSONL files | JSONL records | 说明 |
|---|---:|---:|---:|---|
| quick | 43 | 19 | 533 | mac 可运行，Linux-only 路径按 absent/error 记录。 |
| standard | 69 | 36 | 4358 | mac 可运行，日志/浏览器/包等按可用路径和 absent 记录。 |
| deep | 84 | 46 | 4373 | 归档通过；包含 container/scanner skip 语义。 |
| minimal-safe | 31 | 15 | 341 | mac 可运行。 |
| minimal-safe + tmbrfix | 34 | 17 | 345 | tmbrfix 记录 Linux i386 payload hash/type，mac 上 unsupported skip。 |

deep archive：

```text
/tmp/dfir-e2e-deep.tar.gz
sha256=5e6068dfda1bd2bab65cc1a0010745b958de0c7983b8e59fe26ec50ed41a7488
tar entries=108
```

已验证：

- `legacy/` 和 `ai/` 双轨输出存在。
- `ai/manifest.json` 的 `artifact_count` 与 artifact 列表一致。
- 所有 `ai/**/*.jsonl` 可逐行 JSON 解析。
- deep archive 的 SHA256 与 `ai/archive_summary.json` 一致。
- tar 内包含 `ai/manifest.json` 和 `legacy/SUMMARY`。
- Linux amd64/arm64/386 交叉编译通过。

## Linux VM 必测项

等用户提供 Linux VM 后补测以下项目。

### Runtime Smoke

```sh
make clean
make linux
./dist/dfir-collector-linux-amd64 --profile quick --output /tmp/dfir-quick
./dist/dfir-collector-linux-amd64 --profile standard --output /tmp/dfir-standard
./dist/dfir-collector-linux-amd64 --profile deep --output /tmp/dfir-deep --archive
./dist/dfir-collector-linux-arm64 --profile minimal-safe --output /tmp/dfir-arm64-smoke
./dist/dfir-collector-linux-386 --scan tmbrfix --profile minimal-safe --output /tmp/dfir-386-scanner-smoke
```

### Linux-only Success Paths

- `/proc/[pid]` status/cmdline/maps/fd/exe/cwd/root。
- `/proc/net/*` socket/route/arp/interface，socket inode -> PID/FD。
- `/sys/module`、kernel module path mapping、kernel tainted/cmdline。
- `/etc/sudoers`、systemd units、cron/at、SSH、shell profile。
- Debian/Ubuntu dpkg 和 RHEL-family rpm 包归属。
- `/var/log/auth.log`、`secure`、`syslog`、`messages`、audit、wtmp/btmp/lastlog。
- Chrome/Firefox Linux profiles、locked DB、其他用户权限失败。
- Docker/containerd/Podman/CRI-O/Kubernetes cgroup v1/v2、namespace inode、rootless Podman。
- tmbrfix Linux i386/amd64 32-bit compatibility；YARA/osquery real execution；scanner timeout/permission/clean gating。
- 大采集输出归档耗时、权限失败、跨文件系统输出路径。

### Acceptance

- quick 在 5-10 分钟内完成。
- standard 在默认 timeout 内完成。
- deep 覆盖 container 和 scanner skip/compatibility 语义。
- `legacy/` 与 `ai/` 均生成。
- manifest 完整，artifact hash 可复算。
- JSON/JSONL 全部可解析。
- 归档可解包，archive summary hash 可复算。
- Linux-only 失败必须体现为 absent/error 记录，而不是进程崩溃。
