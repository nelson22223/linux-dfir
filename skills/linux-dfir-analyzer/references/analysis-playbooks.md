# Layer 2 Analysis Playbooks

Layer 2 consumes the Layer 1 analysis pack. It may make judgments, assign confidence, and recommend response actions, but every finding must cite `evidence_line` values and explain gaps or counter-evidence.

## Baseline Order

1. Collection quality: read `collection_quality.json` and note permission limits, absent sources, invalid JSON, truncation, and time range artifacts.
2. Scenario focus: if the user provides a suspected incident type, run that scenario playbook first.
3. Module playbooks: run sessions, persistence, network, process, files/packages, kernel, logs, and container checks.
4. Correlation playbooks: connect entities across facets.
5. Report: write outputs using `report-contract.md`.

## Module Playbooks

### Sessions

Goal: reconstruct account and login activity.

Inputs: `facet_samples/sessions.jsonl`, `facet_samples/logs.jsonl`, `facet_samples/process.jsonl`.

Analyze:

- Accepted and failed SSH/auth events by user, remote address, service, and timestamp.
- Sudo actor, target user, command, cwd, tty, and session continuity.
- wtmp/btmp/lastlog-derived facts versus auth/audit logs.
- Session-to-process links through pid, tty, `process_session_id`, `session_key`, and time.

Output:

- Login summary by user and remote.
- Notable privilege transitions.
- Evidence gaps, such as missing auth logs or permission-limited process fields.

### Persistence

Goal: explain durable execution entries and their target files.

Inputs: `facet_samples/persistence.jsonl`, `facet_samples/files_packages.jsonl`, `facet_samples/process.jsonl`, `facet_samples/network.jsonl`.

Analyze:

- systemd units/drop-ins/enabled links and Exec directives.
- cron/anacron/at schedules, user, command, script path, interpreter, hash, package owner.
- PAM modules, include/substack targets, module path, symlink target, package owner.
- shell profiles, SSH authorized_keys command options, sudoers commands, rc/init/XDG autostart.
- Target file metadata, hash, mtime/ctime, owner, package ownership, and whether any target appears in process or network evidence.

Output:

- Persistence entries grouped by mechanism.
- For each notable entry: entry path, command/target, owner, file hash/package context, linked process/network evidence, confidence.

### Network

Goal: explain exposure and external communication with owner context.

Inputs: `facet_samples/network.jsonl`, `facet_samples/process.jsonl`, `facet_samples/sessions.jsonl`, `facet_samples/container.jsonl`.

Analyze:

- Listeners, outbound flows, local-only sockets, and remote endpoints.
- Socket owner pid/fd/process, command line, exe, package, user, session, cgroup/container.
- DNS runtime/static sources, hosts, routes, DHCP leases, proxy/tunnel config.
- Command-observation differences between Go-native and native command views when present.

Output:

- Listening services and owners.
- Remote endpoints and owner chains.
- DNS/proxy/route context relevant to external communication.

### Process

Goal: reconstruct process execution context.

Inputs: `facet_samples/process.jsonl`, `facet_samples/sessions.jsonl`, `facet_samples/network.jsonl`, `facet_samples/files_packages.jsonl`, `facet_samples/container.jsonl`.

Analyze:

- Parent/child lineage, session, tty, cwd, exe, cmdline, uid/gid.
- Process-to-network links through pid/fd/socket inode.
- Process-to-file links through exe path, cwd, maps, fd, and hash/package ownership.
- Process issues caused by permissions or procfs races.

Output:

- Notable process chains.
- User/session attribution where available.
- Missing context and confidence.

### Files And Packages

Goal: evaluate command replacement and file integrity facts.

Inputs: `facet_samples/files_packages.jsonl`, `facet_samples/process.jsonl`, `facet_samples/persistence.jsonl`.

Analyze:

- `facts/package_integrity` expected versus actual hashes, missing files, conffiles, mode/owner/mtime.
- File hashes and package owner for persistence targets and running executables.
- SUID/SGID, capability, immutable, append-only, recent/tmp/webroot files.
- Unknown-owner or changed files on critical paths.

Output:

- Package integrity anomalies and affected paths.
- Key executable and persistence target file context.
- Evidence needed for manual verification.

### Kernel / Rootkit Clues

Goal: explain kernel-level consistency facts without treating them as scanner verdicts.

Inputs: `facet_samples/kernel.jsonl`, `facet_samples/process.jsonl`, `facet_samples/network.jsonl`, `facet_samples/files_packages.jsonl`.

Analyze:

- `/proc/modules`, `/sys/module`, module file path, hash, package owner, taint, lockdown, LSM/sysctl facts.
- Module present in one source but absent in another.
- Process/socket visibility gaps and permission-limited fields.

Output:

- Kernel consistency observations.
- Rootkit clue confidence and counter-evidence.

### Logs

Goal: turn high-volume logs into a supporting time narrative.

Inputs: `facet_samples/logs.jsonl`, `facet_samples/sessions.jsonl`, `facet_samples/process.jsonl`, `facet_samples/persistence.jsonl`, `facet_samples/network.jsonl`.

Analyze:

- Auth, sudo, audit, syslog, messages, and journal events by timestamp.
- Unit start/stop/failure/restart events linked to systemd units or processes.
- Log source gaps and rotated/compressed source coverage.

Output:

- Timeline highlights and supporting evidence.
- Important log gaps.

### Containers

Goal: explain host/container relationships.

Inputs: `facet_samples/container.jsonl`, `facet_samples/process.jsonl`, `facet_samples/network.jsonl`, `facet_samples/files_packages.jsonl`.

Analyze:

- Runtime, container id, cgroup, namespace, image, mount and host-path context where present.
- Processes and network flows mapped into container context.

Output:

- Container impact summary.
- Host/container attribution for findings.

### Browser

Goal: explain browser-derived user activity metadata when present.

Inputs: `facet_samples/browser.jsonl`, `facet_samples/sessions.jsonl`, `facet_samples/network.jsonl`, `facet_samples/files_packages.jsonl`.

Analyze:

- History, downloads, cookies, and bookmark metadata by user/profile/browser.
- Downloaded file paths and timestamps linked to files/packages or process execution where possible.
- URL/query redaction and raw artifact availability.

Output:

- Browser activity highlights.
- Download/file/network links and evidence gaps.

## Correlation Playbooks

Run these after module playbooks:

- **Login to execution:** remote address -> user/session/tty -> sudo -> process lineage -> file/network.
- **Persistence to execution:** persistence entry -> target script/binary -> hash/package/mtime -> process lineage -> network flow/log event.
- **Network to process:** remote endpoint/listener -> socket inode -> owner pid/fd -> process cmdline/exe/user/session/container -> package/file hash.
- **File integrity to behavior:** modified/missing/unknown-owner path -> running process or persistence target -> log/network evidence.
- **Kernel to visibility:** module/security inconsistency -> process/socket/file visibility gaps -> command-observation differences.
- **Container to host:** container process/network -> cgroup/namespace -> host path mounts -> host files or persistence.

## Scenario Playbooks

If the user gives a suspected issue, prioritize the matching scenario while still recording baseline coverage.

### Suspected Malware / Backdoor

Focus: persistence, process, network, files/packages, logs.

Look for durable launch entries, recently changed executable/script targets, outbound flows, unknown-owner files, and session/process links.

### Suspected C2 / External Connection

Focus: network, process, DNS/proxy/tunnel, sessions.

Start from remote endpoints, then link to owner process, user/session/container, executable hash/package, and DNS/proxy sources.

### Suspected Webshell

Focus: files/packages, process, logs, network.

Start from webroot/recent/tmp files, web service users/processes, shell-like child processes, and outbound connections.

### Suspected Miner

Focus: process, network, files/packages, persistence.

Look for long-running CPU-heavy process hints if present, mining pool-like network endpoints only as a hypothesis, persistence targets, tmp/dev/shm execution, and package ownership.

### Suspected Ransomware

Focus: sessions, process, files/packages, logs.

Look for recent login/sudo activity, broad file mutation timelines, unusual processes, deleted/renamed files if captured, and service stop/log events.

### Suspected Credential Theft

Focus: sessions, process, browser, files/packages, logs.

Look for browser raw metadata, shell history/log access where collected, auth failures/successes, suspicious archive/copy commands if present, and outbound flows.

### Suspected Rootkit / Command Replacement

Focus: kernel, files/packages, process, network, command observations.

Start from kernel consistency and package integrity facts, then compare running executable paths, command observation metadata, and socket/process visibility.

## Finding Rules

Each finding must include:

- Title
- Hypothesis or conclusion
- Confidence: `low`, `medium`, or `high`
- Evidence references: one or more `evidence_line` values
- Correlated entities: user, process, file, package, socket, unit, container where available
- Counter-evidence or gaps
- Suggested next validation step

Do not write a finding when the only evidence is a missing source, permission error, or `exists=false` status. Report those under collection quality.
