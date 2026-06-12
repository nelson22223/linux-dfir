# Linux DFIR Evidence 合并输出设计

生成时间：2026-06-03

## 1. 输出原则

1. AI 结构化证据只进入 `ai/evidence.jsonl`。
2. 工具只做采集，不做分析判断；输出事实、来源、采集状态，不输出风险标签、严重性、verdict 或分析结论。
3. 尽可能按稳定实体 identity 合并字段：如果采集位置 A 得到 `a/b/c`，采集位置 B 得到 `a/d/e`，且二者指向同一实体，则输出一行包含 `a/b/c/d/e` 的事实对象。
4. 合并时保留来源，不丢证据链：每个合并对象应有 `sources[]`，记录 source_path、source_type、source_trust、raw_artifact_ref 或 legacy_ref。
5. 不强行合并天然多事件数据：日志事件、浏览器历史、下载记录、scanner findings、timeline event 这类以时间为主轴的事实，应一事件一行。
6. 合并冲突不做裁决：同一字段出现多个不同观察值时，保留 `observed_values[]` 或按来源分组，交给后续 AI agent/人工分析。

## 2. 全局 Record 形态

每行仍是统一 envelope：

```json
{
  "schema_version": "linux-dfir/v1",
  "case_id": "...",
  "host_id": "...",
  "session_id": "...",
  "collector": "process",
  "record_type": "process",
  "stream": "entities/process",
  "source_path": "/proc/123",
  "source_type": "procfs",
  "source_trust": "high",
  "collected_at": "...",
  "raw_artifact_ref": "ai/evidence.jsonl",
  "data": {
    "entity_id": "process:123",
    "pid": 123,
    "facts": {},
    "sources": []
  }
}
```

`data` 内只放事实字段，不重复 envelope metadata。

## 3. 模块合并目标

| 模块 | 当前核心输出 | 合并 identity | 目标核心 record | 合并策略 |
|---|---|---|---|---|
| host | `host_profile`、ssh host key metadata | `host_id` | `entities/host` | 一行合并 OS/kernel/arch/hostname/uptime/cpu/mem/os_release/ssh_host_keys。ssh key 只记录 metadata、fingerprint/hash，不记录私钥内容。 |
| system | meminfo、cpuinfo、vmstat legacy | `host_id` | `entities/host` | minimal 中并入 host 的 `resources`；legacy 仍保留 meminfo/cpuinfo/vmstat 文本。deep/standard 如需独立资源快照，应避免和 host 重复。 |
| time | localtime/timezone/NTP facts | `host_id` | `facts/time` | 一行包含 timezone、localtime link、UTC offset、current time snapshot、NTP config/status facts。 |
| disk | mounts、mountinfo | mount identity: mount_point + device/root | `entities/mount` | 每个 mount 一行，合并 `/etc/mtab`/`/proc/mounts`/`mountinfo` 字段，包含 fs type、options、major_minor、propagation、source。 |
| users | passwd、group | user: uid/name；group: gid/name | `entities/user`、`entities/group` | 用户一行合并 passwd、primary group、supplementary groups、home/shell。group 一行合并 group members。不要输出“风险标签”，只输出事实如 `login_shell=true` 这类客观布尔值。 |
| kernel | modules、sysfs module metadata、module file path | module name | `entities/kernel_module` | 每个 module 一行，合并 proc modules、sysfs version/srcversion/holders、module_path、file metadata/hash/package owner。kernel cmdline/taint 用 `facts/kernel` 一行。 |
| process | process、maps、fds、entities | pid + start_time；当前先 pid | `entities/process` | 每个进程一行，合并 status/cmdline/environ summary/exe/cwd/root/maps summary/fds[]/socket owners/cgroup/ns/capabilities。fd 和 maps 不再单独拆成多行，除非超过大小上限进入 raw/分页。 |
| network | connections、listeners、routes、arp、interfaces | socket inode；route key；if name；arp ip+dev | `entities/socket`、`entities/interface`、`facts/routes`、`facts/arp` | socket 一行合并 connection/listener/owners/process refs/local/remote/unix path。接口一行合并 dev stats、IPv4/IPv6/MAC/link facts。routes 可按 route 一行或 `facts/routes` 数组。未采集的 firewall 不作为事实输出。 |
| persistence | files、items、cron、systemd units | file path；unit name；cron source+line | `entities/persistence_file`、`entities/systemd_unit`、`facts/cron_entries` | 同一文件一行合并 file metadata、parsed items、raw copy refs。systemd unit 一行合并 unit file、install section、exec lines、enabled symlink facts。 |
| files | files、hashes、suid/open/recent/file observations | path + inode/dev when available | `entities/file` | 每个文件一行合并 stat、hashes、symlink target、open_by[]、recent timestamps、mode bits、package owner。`suid/world_writable/deleted_open` 作为事实原因字段，不作为风险标签。 |
| packages | packages、file owners | package key；file path | `entities/package`、合并进 `entities/file.package_owner` | package 一行合并 dpkg/rpm facts。file ownership 优先并入 `entities/file`；若文件未被 files collector 采到，仍输出一行 minimal file owner fact。 |
| browser | profiles、history、downloads、cookies、bookmarks | profile id；event row id/time/url | `entities/browser_profile`、`events/browser_history`、`events/browser_download`、`facts/browser_cookie_metadata`、`events/browser_bookmark` | profile 一行合并 profile metadata/raw DB refs。history/download/bookmark 是事件，保留一条一行。cookie 只输出 metadata，不输出 secret value。 |
| logs | auth/log/audit events、raw copy refs | event source + timestamp + normalized text hash | `events/log` | 日志天然是事件，不合并到一行；但同一日志行被 auth/log 两个 parser 命中时应合并为同一 event，union event_types[]。 |
| container | containers、container_processes、process_containers、namespaces、cgroups、runtime metadata、entities | container id；pid | `entities/container`、并入 `entities/process.container` | container 一行合并 runtime metadata/cgroups/namespaces/process refs。process container 关系并入 process record 的 `container` 字段，同时在 container record 中保留 `processes[]` refs。 |
| scanner | scanner runs、scanner findings | run id；finding target + scanner + signature | `facts/scanner_run`、`events/scanner_finding` | run 一行；finding 一条一行。只记录 scanner 输出事实，不给本工具自己的恶意 verdict。 |
| archive | archive_summary、manifest/artifact_index | archive path/session id | control JSON, not evidence event | 控制文件保持 JSON，不进入事件判断。可选在 evidence 中写一条 `facts/archive`，只记录 archive path/hash/size。 |

## 4. Minimal Profile 优先合并顺序

minimal-safe 当前模块：host、system、users、process、network。优先级：

1. `entities/process`：合并 `parsed/processes`、`parsed/process_maps`、`parsed/process_fds`、`entities`。
2. `entities/socket`：合并 `parsed/network_connections`、`parsed/listeners`，用 inode 关联 process refs。
3. `entities/user` / `entities/group`：合并 passwd/group，用户记录包含 supplementary_groups。
4. `entities/host`：合并 host_profile、system mem/cpu、ssh_host_keys。
5. `entities/interface` / `facts/routes` / `facts/arp`：网络基础事实合并。

当前实现状态（2026-06-03）：

- 已实现：`entities/host` 合并 host profile + `/proc/meminfo` + `/proc/cpuinfo` + SSH host key metadata/hash。
- 已实现：system collector 仅保留 `/proc/meminfo`、`/proc/cpuinfo`、`vmstat -s` legacy 文本；AI 资源事实并入 `entities/host.resources`。
- 已实现：`entities/user` 合并 passwd + group，包含 primary group 和 supplementary groups；`entities/group` 按 group 输出。
- 已实现：`entities/process` 按 PID 输出一行，合并 status/cmdline/environ summary/exe/cwd/root/maps summary/fds/fd issues/entity id。
- 已实现：`entities/socket` 按 socket identity 输出一行，合并 connection/listener/owner facts；不再输出单独 `parsed/listeners`。
- 已实现：`entities/interface`、`facts/routes`、`facts/arp` 作为 minimal 网络基础事实输出；未采集的 firewall 不再写事实 record。
- 已验证：Ubuntu ARM64 VM root minimal-safe 运行下 `parsed/process_fds=0`、`parsed/process_maps=0`、`parsed/network_connections=0`、`parsed/listeners=0`、`facts/system_resource=0`、`facts/firewall=0`、`error_event=0`、metadata duplicate=0。

## 5. 大对象和上限

合并不是无限展开。对于 fds、maps、history、logs 等可能很大的数组：

- process fds 可内联前 N 个完整事实，同时记录 `fd_count`，超限部分写 `ai/raw/` 或继续按 `stream=entities/process_fd` 分页事实。
- maps 默认保留 summary 和 sample_paths；完整 maps 可作为 raw artifact。
- logs/browser history 保持事件流，不并入 host/profile 单行。

## 6. 后续实现建议

1. 先实现 output 层的 `AppendMergedJSONL(identity, patch)` 或 collector 内聚合 map，最终一次性 flush。
2. minimal-safe 先做 process/socket/user/host 合并。
3. standard/deep 再扩展 file/package/persistence/container/browser/logs 合并。
4. 每个模块测试必须断言：同一 identity 的多来源事实输出为一条 record，字段为 union，且 `sources[]` 保留来源。
