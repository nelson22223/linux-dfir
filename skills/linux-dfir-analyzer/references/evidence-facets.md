# Evidence Facets

Use facets as model-sized slices over `ai/evidence.jsonl`. A single stream may feed multiple facets; keep evidence references instead of copying full records into reports.

## sessions

Purpose: reconstruct who logged in, from where, on which tty/session, and what sudo/auth activity followed.

Typical streams:

- `facts/session_observations`
- `facts/auth_events`
- `facts/audit_events`
- `facts/log_events`
- `timeline`

Useful fields: `user`, `target_user`, `remote_addr`, `tty`, `pid`, `session_key`, `login_session_id`, `command`, `cwd`, `timestamp`, `source_file`, `raw_copy_ref`.

## persistence

Purpose: explain durable or delayed execution entries.

Typical streams:

- `facts/persistence_items`
- `facts/cron_entries`
- `facts/pam_persistence`
- `entities/systemd_unit`
- `entities/persistence_file`

Useful fields: `category`, `item_type`, `path`, `command`, `commands`, `exec_directives`, `target_path`, `script_path`, `sha256`, `package_owner`, `enabled_hint`.

## network

Purpose: connect sockets and flows to processes, users, routes, DNS, proxy/tunnel configuration, and containers.

Typical streams:

- `facts/network_flows`
- `entities/socket`
- `facts/dns_config`
- `facts/routes`
- `facts/arp`
- `facts/dhcp_leases`
- `facts/network_persistence`
- `facts/network_counters`
- `facts/command_observations`

Useful fields: `flow_kind`, `socket`, `remote_addr`, `remote_address`, `remote_port`, `owner_pids`, `owner_processes`, `owner_lineage_keys`, `route_interface_hint`, `dns_source_hint`, `container_ids`.

## process

Purpose: reconstruct execution chain and process context.

Typical streams:

- `entities/process`
- `facts/process_lineage`

Useful fields: `pid`, `ppid`, `lineage_key`, `parent_key`, `cmdline`, `exe`, `cwd`, `uid`, `gid`, `process_session_id`, `tty`, `cgroup_lines`, `namespaces`, `issues`.

## files_packages

Purpose: evaluate command replacement and file/package integrity evidence.

Typical streams:

- `entities/file`
- `facts/file_hashes`
- `facts/file_attributes`
- `facts/file_package_owners`
- `facts/package_integrity`
- `entities/package`

Useful fields: `path`, `sha256`, `hash_available`, `package_name`, `package_key`, `expected_md5`, `actual_md5`, `file_exists`, `package_conffile`, `mode`, `uid`, `gid`, `mtime`, `ctime`, `capability`, `immutable`, `append_only`.

## kernel

Purpose: support rootkit clue analysis from consistency facts, not collector verdicts.

Typical streams:

- `entities/kernel_module`
- `facts/kernel_consistency`
- `facts/kernel_security`

Useful fields: `module`, `name`, `path`, `sha256`, `loaded`, `proc_present`, `sysfs_present`, `tainted`, `lockdown`, `lsm`, `sysctl`.

## logs

Purpose: build time-ordered supporting evidence from auth, syslog, audit, and journal.

Typical streams:

- `facts/log_events`
- `facts/auth_events`
- `facts/audit_events`
- `facts/journal_events`
- `timeline`

Useful fields: `timestamp`, `event_type`, `unit`, `pid`, `uid`, `message`, `command`, `service`, `source_file`, `raw_copy_ref`, `line_number`.

## container

Purpose: map process/network/file evidence into container or namespace context.

Typical streams:

- `entities/container`
- `facts/container_*`
- `facts/process_lineage`
- `facts/network_flows`

Useful fields: `container_id`, `runtime`, `pod`, `namespace`, `image`, `cgroup`, `pid`, `mounts`, `host_path`.

## browser

Purpose: summarize browser activity metadata without treating raw browser databases as model input.

Typical streams:

- Browser collector records for profiles, history, downloads, cookies, bookmarks, and raw copy metadata.

Useful fields: `browser_name`, `profile_name`, `user`, `url`, `host`, `download_path`, `timestamp`, `raw_copy_ref`, `source_path`.

## quality

Purpose: keep collection limitations separate from security conclusions.

Typical streams:

- `errors`
- status records
- absent facts
- records with permission-denied issues

Useful fields: `collector`, `error`, `absent_reason`, `exists`, `source_path`, `source_type`, `source_trust`, `issues`.

## timeline

Purpose: provide a lightweight ordering surface for follow-up analysis.

Typical streams:

- `timeline`
- timestamped facts copied into other facets

Useful fields: `timestamp`, `event`, `collector`, `summary`, `evidence_line`, `source_path`.
