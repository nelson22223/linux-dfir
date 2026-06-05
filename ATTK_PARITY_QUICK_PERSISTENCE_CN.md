# Quick Persistence ATTK Parity Gate

生成时间：2026-06-03

## 1. 本轮原则

1. 只增不减：原 ATTK `AutorunInfo` 采集面必须保留；Go 版可以新增 systemd、SSH、shell profile、sudoers、XDG 等现代持久化点，但不能丢原版路径。
2. AI 结构化输出仍只进入 `ai/evidence.jsonl`。
3. 工具只采集事实，不输出风险标签、verdict、severity 或分析结论。
4. 同一文件/同一 unit/同一 cron 行尽可能合并为稳定 identity 的一条 JSON record，并保留 `sources[]`。
5. legacy 原始文本/文件复制兼容输出必须保留；敏感内容如 SSH private key 不复制正文，只记录 metadata/hash/redaction fact。
6. 原 ATTK autorun 面的 legacy copy 不做静默小尺寸截断；若后续引入全局采集上限，必须在 AI fact 中明确标记 copy/truncate 状态。

## 2. 原 ATTK AutorunInfo 证据面

本地证据：`attk_extracted/attklnx.sh:455-494`。

| 原 ATTK 采集面 | 原实现 | Go quick 要求 | 当前状态 |
|---|---|---|---|
| `/etc/at.allow` | `cp -p` | legacy copy + AI file fact | 已补 |
| `/etc/at.deny` | `cp -p` | legacy copy + AI file fact | 已补 |
| `/etc/inittab` | `cp -p` | legacy copy + AI file fact + parsed lines | 已覆盖 |
| `/etc/cron*` | `cp -RpL` | 覆盖 `/etc/crontab`、`/etc/cron.d*`、`/etc/cron.{allow,deny}`、周期目录等 glob 命中项 | 已补 |
| `/etc/rc*` | `cp -RpL` | 覆盖 `/etc/rc.local`、`/etc/rc*.d` 和 glob 命中项 | 已补 |
| `/var/spool/cron/crontabs` | `cp -RpL` | legacy copy + cron parse | 已覆盖 |
| `/var/spool/cron` | `cp -RpL` | legacy copy + cron parse | 已覆盖 |
| `/var/cron/tabs` | `cp -RpL` | legacy copy + cron parse | 已补 |
| `/var/spool/at` | `cp -RpL` | legacy copy + at job fact | 已覆盖 |
| `/var/at/jobs` | `cp -RpL` | legacy copy + at job fact | 已补 |
| `/etc/init` | `cp -RpL` | legacy copy + init/upstart facts | 已覆盖 |
| `/etc/init.d` | `cp -RpL` | legacy copy + init script facts | 已覆盖 |
| `/var/log/cron` | `cp -p` | legacy copy + AI file fact; log parsing belongs to logs module | 已补 |

## 3. Go 版新增面

这些属于只增不减中的新增能力，quick 优化不能删除：

- systemd system/user units and timers：`/etc/systemd/*`、`/lib/systemd/*`、`/usr/lib/systemd/*`、`/run/systemd/*`、用户级 `.config/systemd/user`。
- SSH：`sshd_config`、`ssh_config`、用户 `.ssh/authorized_keys`、private key metadata redaction。
- Shell profile：`/etc/profile`、`/etc/profile.d`、用户 `.profile/.bashrc/.zshrc/...`。
- sudoers：`/etc/sudoers`、`/etc/sudoers.d`。
- XDG autostart：`/etc/xdg/autostart`、用户 `.config/autostart`。

## 4. AI 合并目标

| 输出 stream | identity | 内容 |
|---|---|---|
| `entities/persistence_file` | `path` | 文件/目录 metadata、hash、legacy path、redaction、parsed item summary、sources |
| `entities/systemd_unit` | unit source path 或 unit name + path | unit 文件 metadata、unit name、unit type、ExecStart/OnCalendar 等 directives、enabled hint、user、sources |
| `facts/cron_entries` | source path + line number + command hash | cron schedule、user、command、source file hash、sources |

不再新增 `parsed/persistence_files`、`parsed/persistence_items`、`parsed/cron_entries`、`parsed/systemd_units` 这类模块级碎片 stream。

## 5. 验收标准

- `quick` root Linux VM 运行后：
  - `ai/evidence.jsonl` 是唯一 AI JSONL 文件。
  - `parsed/persistence_files=0`
  - `parsed/persistence_items=0`
  - `parsed/cron_entries=0`
  - `parsed/systemd_units=0`
  - 原 ATTK AutorunInfo 路径全部有 legacy copy 或明确 `exists=false` absent record；预期可不存在的路径不写入 `errors`。
  - private key 内容不出现在输出树。
  - `entities/persistence_file`、`entities/systemd_unit`、`facts/cron_entries` 均为合法 JSONL record。
- subagent review/test gate 必须 PASS，blocking 为 0。
