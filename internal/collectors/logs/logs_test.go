package logs

import (
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"linux-dfir/internal/collectors/common"
	"linux-dfir/internal/evidence"
	"linux-dfir/internal/output"
)

func TestParseSyslogAndAuditLines(t *testing.T) {
	event, ok := ParseSyslogLine("Jun  1 12:34:56 host1 sshd[123]: Accepted publickey for alice from 192.0.2.10 port 5555 ssh2", 2026)
	if !ok {
		t.Fatal("expected syslog parse")
	}
	if event.LogType != "auth" || event.EventType != "ssh_accepted" || event.Service != "sshd" || event.PID != 123 {
		t.Fatalf("unexpected syslog event: %#v", event)
	}
	if event.User != "alice" || event.RemoteAddr != "192.0.2.10" {
		t.Fatalf("missing auth hints: %#v", event)
	}
	if event.Timestamp == nil || event.Timestamp.Year() != 2026 || !event.TimeInferred {
		t.Fatalf("missing timestamp/inference flag: %#v", event)
	}
	iso, _ := ParseSyslogLine("2026-06-03T04:52:27.141735+00:00 linux-dfir sshd[321]: Failed password for invalid user bob from 198.51.100.7 port 4444 ssh2", 2026)
	if iso.LogType != "auth" || iso.EventType != "ssh_failed" || iso.Service != "sshd" || iso.PID != 321 {
		t.Fatalf("unexpected ISO syslog event: %#v", iso)
	}
	if iso.Timestamp == nil || iso.Timestamp.Year() != 2026 || iso.TimeInferred {
		t.Fatalf("unexpected ISO timestamp flags: %#v", iso)
	}
	if iso.User != "bob" || iso.RemoteAddr != "198.51.100.7" {
		t.Fatalf("missing ISO auth hints: %#v", iso)
	}
	su, _ := ParseSyslogLine("Jun  1 12:35:56 host1 su: pam_unix(su:session): session opened for user root by alice(uid=1000)", 2026)
	if su.EventType != "su_session" {
		t.Fatalf("unexpected su event: %#v", su)
	}
	sudo, _ := ParseSyslogLine("Jun  1 12:35:57 host1 sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id", 2026)
	if sudo.User != "alice" || sudo.Command != "/usr/bin/id" || sudo.Fields["actor_user"] != "alice" || sudo.Fields["target_user"] != "root" {
		t.Fatalf("unexpected sudo hints: %#v", sudo)
	}
	sudoSession, _ := ParseSyslogLine("Jun  1 12:35:58 host1 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by alice(uid=1000)", 2026)
	if sudoSession.User != "alice" || sudoSession.Fields["actor_user"] != "alice" || sudoSession.Fields["target_user"] != "root" || sudoSession.Fields["session_action"] != "opened" {
		t.Fatalf("unexpected sudo session hints: %#v", sudoSession)
	}
	cron, _ := ParseSyslogLine("Jun  1 12:36:56 host1 cron[1]: (root) CMD (/usr/bin/true)", 2026)
	if cron.EventType != "cron" {
		t.Fatalf("unexpected cron event: %#v", cron)
	}

	audit := ParseAuditLine(`type=USER_LOGIN msg=audit(1700000000.125:42): pid=222 uid=0 auid=1000 ses=1 comm="sshd" acct="alice" addr=192.0.2.10 res=success`)
	if len(audit) != 1 {
		t.Fatalf("expected one audit event, got %d", len(audit))
	}
	if audit[0].EventType != "audit_auth" || audit[0].User != "alice" || audit[0].Command != "sshd" {
		t.Fatalf("unexpected audit event: %#v", audit[0])
	}
	if audit[0].PID != 222 || audit[0].SessionID != 1 || audit[0].RemoteAddr != "192.0.2.10" {
		t.Fatalf("missing audit session hints: %#v", audit[0])
	}
	if audit[0].Timestamp == nil || audit[0].Timestamp.Unix() != 1700000000 {
		t.Fatalf("unexpected audit timestamp: %#v", audit[0].Timestamp)
	}
	if audit[0].Fields["type"] != "USER_LOGIN" || audit[0].Fields["addr"] != "192.0.2.10" {
		t.Fatalf("missing audit fields: %#v", audit[0].Fields)
	}
}

func TestParseLinuxLoginAccountingRecords(t *testing.T) {
	loginAt := time.Date(2026, 6, 3, 4, 52, 27, 0, time.UTC)
	wtmp := buildUtmpRecord(t, 7, 1234, "pts/0", "p0", "alice", "192.0.2.10", loginAt)
	events := parseUtmpRecords(wtmp, "wtmp")
	if len(events) != 1 {
		t.Fatalf("got %d wtmp events", len(events))
	}
	if events[0].EventType != "login_success" || events[0].User != "alice" || events[0].TTY != "pts/0" || events[0].RemoteAddr != "192.0.2.10" {
		t.Fatalf("unexpected wtmp event: %#v", events[0])
	}
	if events[0].Timestamp == nil || !events[0].Timestamp.Equal(loginAt) {
		t.Fatalf("unexpected wtmp timestamp: %#v", events[0].Timestamp)
	}
	arm64 := buildUtmpRecord400(t, 7, 2345, "pts/2", "p2", "carol", "", "198.51.100.42", loginAt)
	arm64Events := parseUtmpRecords(arm64, "wtmp")
	if len(arm64Events) != 1 {
		t.Fatalf("got %d arm64 wtmp events", len(arm64Events))
	}
	if arm64Events[0].EventType != "login_success" || arm64Events[0].RemoteAddr != "198.51.100.42" || arm64Events[0].Timestamp == nil || !arm64Events[0].Timestamp.Equal(loginAt) {
		t.Fatalf("unexpected 400-byte utmp event: %#v", arm64Events[0])
	}

	btmpEvents := parseUtmpRecords(wtmp, "btmp")
	if len(btmpEvents) != 1 || btmpEvents[0].EventType != "login_failed" {
		t.Fatalf("unexpected btmp event: %#v", btmpEvents)
	}

	lastlog := make([]byte, 296*1001)
	copy(lastlog[296*1000:], buildLastlogRecord(t, loginAt, "pts/1", "203.0.113.5"))
	lastEvents := parseLastlogRecords(lastlog)
	if len(lastEvents) != 1 {
		t.Fatalf("got %d lastlog events", len(lastEvents))
	}
	if lastEvents[0].EventType != "last_login" || lastEvents[0].UID != 1000 || lastEvents[0].TTY != "pts/1" || lastEvents[0].RemoteAddr != "203.0.113.5" {
		t.Fatalf("unexpected lastlog event: %#v", lastEvents[0])
	}
}

func TestCollectWithFixtureLogsAndGzip(t *testing.T) {
	root := t.TempDir()
	restore := setLogTestHooks(root)
	defer restore()

	writeFixtureFile(t, rootPath(root, "/var/log/auth.log"), "Jun  1 12:34:56 host1 sshd[123]: Accepted password for alice from 192.0.2.10 port 5555 ssh2\nJun  1 12:35:01 host1 sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id --api-key \"super-secret-log\"\n2026-06-03T04:52:27.141735+00:00 host1 sshd[321]: Failed password for invalid user bob from 198.51.100.7 port 4444 ssh2\n", 0o640)
	writeFixtureFile(t, rootPath(root, "/var/log/audit/audit.log"), "type=USER_LOGIN msg=audit(1700000000.125:42): pid=222 uid=0 auid=1000 ses=1 comm=\"sshd\" acct=\"alice\" addr=192.0.2.10 res=success\n", 0o640)
	writeFixtureBytes(t, rootPath(root, "/var/log/wtmp"), buildUtmpRecord(t, 7, 1234, "pts/0", "p0", "alice", "192.0.2.10", time.Date(2026, 6, 3, 4, 52, 27, 0, time.UTC)), 0o640)
	writeFixtureBytes(t, rootPath(root, "/var/run/utmp"), buildUtmpRecord(t, 7, 5678, "pts/3", "p3", "alice", "192.0.2.10", time.Date(2026, 6, 3, 5, 1, 0, 0, time.UTC)), 0o640)
	lastlog := make([]byte, 296*1001)
	copy(lastlog[296*1000:], buildLastlogRecord(t, time.Date(2026, 6, 3, 4, 52, 27, 0, time.UTC), "pts/1", "203.0.113.5"))
	writeFixtureBytes(t, rootPath(root, "/var/log/lastlog"), lastlog, 0o640)
	writeGzipFixture(t, rootPath(root, "/var/log/auth.log.1.gz"), "Jun  1 13:00:00 host1 sshd[456]: Failed password for invalid user bob from 198.51.100.7 port 4444 ssh2\n")

	out, outDir := newOutput(t)
	if err := Collect(context.Background(), out); err != nil {
		t.Fatal(err)
	}

	evidencePath := filepath.Join(outDir, "ai/evidence.jsonl")
	assertFileContains(t, filepath.Join(outDir, "ai/raw/logs/var_log_auth.log"), "Accepted password")
	assertFileContains(t, filepath.Join(outDir, "legacy/logs/var_log_auth.log"), "COMMAND=/usr/bin/id")
	assertFileExists(t, filepath.Join(outDir, "ai/raw/logs/var_log_auth.log.1.gz"))
	assertFileContains(t, evidencePath, `"event_type":"ssh_accepted"`)
	assertFileContains(t, evidencePath, `"event_type":"sudo_command"`)
	assertFileContains(t, evidencePath, `"event_type":"ssh_failed"`)
	assertFileContains(t, evidencePath, `/usr/bin/id --api-key \"[redacted]\"`)
	assertFileNotContains(t, evidencePath, "super-secret-log")
	assertFileContains(t, evidencePath, `"source_file":"/var/log/auth.log.1.gz"`)
	assertFileContains(t, evidencePath, `"source_file":"/var/log/secure"`)
	assertFileContains(t, evidencePath, `"event_type":"audit_auth"`)
	assertFileContains(t, evidencePath, `"event_type":"raw_log_copy"`)
	assertFileContains(t, evidencePath, `"record_subtype":"status"`)
	assertFileContains(t, evidencePath, `"stream":"facts/login_events"`)
	assertFileContains(t, evidencePath, `"event_type":"login_success"`)
	assertFileContains(t, evidencePath, `"event_type":"last_login"`)
	assertFileContains(t, evidencePath, `"uid":1000`)
	assertFileContains(t, evidencePath, `"source_file":"/var/log/wtmp"`)
	assertFileContains(t, evidencePath, `"source_file":"/var/log/lastlog"`)
	assertFileContains(t, evidencePath, "Accepted password for alice")
	assertFileContains(t, evidencePath, "audit(1700000000.125:42)")

	assertEvidenceRecord(t, evidencePath, "facts/session_observations", map[string]any{
		"observation_type": "auth_log",
		"event_type":       "sudo_command",
		"source_file":      "/var/log/auth.log",
		"user":             "alice",
		"target_user":      "root",
		"tty":              "pts/0",
		"cwd":              "/home/alice",
		"command":          `/usr/bin/id --api-key "[redacted]"`,
	})
	assertEvidenceRecord(t, evidencePath, "facts/session_observations", map[string]any{
		"observation_type": "auth_log",
		"event_type":       "audit_auth",
		"source_file":      "/var/log/audit/audit.log",
		"user":             "alice",
		"remote_addr":      "192.0.2.10",
		"pid":              222,
		"login_session_id": 1,
		"session_key":      "user=alice|remote=192.0.2.10|session=1|pid=222",
	})
	assertEvidenceRecord(t, evidencePath, "facts/session_observations", map[string]any{
		"observation_type": "login_accounting",
		"event_type":       "login_success",
		"source_file":      "/var/run/utmp",
		"user":             "alice",
		"remote_addr":      "192.0.2.10",
		"tty":              "pts/3",
		"session_key":      "user=alice|remote=192.0.2.10|tty=pts/3|session=1|pid=5678",
		"pid":              5678,
		"login_session_id": 1,
	})

	assertJSONL(t, evidencePath)
}

func TestCollectMissingRootWritesAbsentAndErrors(t *testing.T) {
	root := t.TempDir()
	restore := setLogTestHooks(filepath.Join(root, "missing-root"))
	defer restore()

	out, outDir := newOutput(t)
	if err := Collect(context.Background(), out); err != nil {
		t.Fatal(err)
	}

	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"exists":false`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"/var/log/auth.log"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"source_file":"/var/log/audit/audit.log"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"source_file":"/var/log/wtmp"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"source_file":"/var/log/lastlog"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"source_file":"/var/run/utmp"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "/var/log/auth.log")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "/var/log/lastlog")
	assertFileNotContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"stream":"errors"`)
}

func TestCollectJournalJSONEvents(t *testing.T) {
	restore := setJournalRunnerForTest(func(ctx context.Context, command string, args ...string) common.CommandResult {
		if command != "journalctl" {
			t.Fatalf("unexpected command %s", command)
		}
		gotArgs := strings.Join(args, " ")
		wantArgs := "-o json --no-pager -n 1000"
		if gotArgs != wantArgs {
			t.Fatalf("journalctl args = %q want %q", gotArgs, wantArgs)
		}
		output := `{"__REALTIME_TIMESTAMP":"1780471947141735","MESSAGE":"Started service --api-key super-secret-log","_SYSTEMD_UNIT":"ssh.service","SYSLOG_IDENTIFIER":"sshd","_PID":"123","_UID":"0","_GID":"0","_BOOT_ID":"boot-1","PRIORITY":"5","_TRANSPORT":"syslog","__CURSOR":"cursor-1","__MONOTONIC_TIMESTAMP":"999"}` + "\n"
		return common.CommandResult{Command: command, Args: args, Output: []byte(output), Path: "/usr/bin/journalctl"}
	})
	defer restore()

	out, outDir := newOutput(t)
	if err := collectJournal(context.Background(), out); err != nil {
		t.Fatal(err)
	}

	evidencePath := filepath.Join(outDir, "ai/evidence.jsonl")
	assertFileContains(t, filepath.Join(outDir, "ai/raw/logs/journalctl_json.out"), "Started service --api-key super-secret-log")
	assertFileContains(t, filepath.Join(outDir, "legacy/logs/journalctl_json.out"), "Started service --api-key super-secret-log")
	assertEvidenceRecord(t, evidencePath, "facts/journal_events", map[string]any{
		"exists":              true,
		"message":             "Started service --api-key [redacted]",
		"unit":                "ssh.service",
		"syslog_identifier":   "sshd",
		"pid":                 123,
		"uid":                 0,
		"gid":                 0,
		"boot_id":             "boot-1",
		"priority":            5,
		"transport":           "syslog",
		"cursor":              "cursor-1",
		"monotonic_timestamp": "999",
		"raw_copy_ref":        "ai/raw/logs/journalctl_json.out",
	})
	assertFileContains(t, evidencePath, `"timestamp":"2026-06-03T07:32:27.141735Z"`)
	assertFileNotContains(t, evidencePath, "super-secret-log")
	assertJSONL(t, evidencePath)
}

func TestCollectJournalMissingWritesStatus(t *testing.T) {
	restore := setJournalRunnerForTest(func(ctx context.Context, command string, args ...string) common.CommandResult {
		return common.CommandResult{Command: command, Args: args, Err: exec.ErrNotFound}
	})
	defer restore()

	out, outDir := newOutput(t)
	if err := collectJournal(context.Background(), out); err != nil {
		t.Fatal(err)
	}

	assertEvidenceRecord(t, filepath.Join(outDir, "ai/evidence.jsonl"), "facts/journal_events", map[string]any{
		"exists":         false,
		"record_subtype": "status",
		"status":         "absent",
		"absent_reason":  "journalctl not found",
	})
}

func TestCollectJournalCommandFailureWritesStatus(t *testing.T) {
	restore := setJournalRunnerForTest(func(ctx context.Context, command string, args ...string) common.CommandResult {
		return common.CommandResult{Command: command, Args: args, Output: []byte("failed token=super-secret-log\n"), Err: errors.New("exit status 1")}
	})
	defer restore()

	out, outDir := newOutput(t)
	if err := collectJournal(context.Background(), out); err != nil {
		t.Fatal(err)
	}

	evidencePath := filepath.Join(outDir, "ai/evidence.jsonl")
	assertEvidenceRecord(t, evidencePath, "facts/journal_events", map[string]any{
		"exists":        false,
		"status":        "error",
		"absent_reason": "exit status 1: failed token=[redacted]",
		"error":         "exit status 1",
	})
	assertFileNotContains(t, evidencePath, "super-secret-log")
}

func TestCollectJournalRedactsPrivateKeyBlock(t *testing.T) {
	restore := setJournalRunnerForTest(func(ctx context.Context, command string, args ...string) common.CommandResult {
		message := "leaked -----BEGIN OPENSSH PRIVATE KEY-----\\nsecret-key-body\\n-----END OPENSSH PRIVATE KEY-----"
		output := `{"__REALTIME_TIMESTAMP":"1780471947141735","MESSAGE":"` + message + `","_SYSTEMD_UNIT":"demo.service"}`
		return common.CommandResult{Command: command, Args: args, Output: []byte(output + "\n"), Path: "/usr/bin/journalctl"}
	})
	defer restore()

	out, outDir := newOutput(t)
	if err := collectJournal(context.Background(), out); err != nil {
		t.Fatal(err)
	}

	evidencePath := filepath.Join(outDir, "ai/evidence.jsonl")
	assertFileContains(t, evidencePath, "leaked [redacted]")
	assertFileNotContains(t, evidencePath, "BEGIN OPENSSH PRIVATE KEY")
	assertFileNotContains(t, evidencePath, "secret-key-body")
	assertFileNotContains(t, evidencePath, "END OPENSSH PRIVATE KEY")
}

func TestCollectJournalInvalidJSONWritesStatus(t *testing.T) {
	restore := setJournalRunnerForTest(func(ctx context.Context, command string, args ...string) common.CommandResult {
		return common.CommandResult{Command: command, Args: args, Output: []byte("{not-json\n"), Path: "/usr/bin/journalctl"}
	})
	defer restore()

	out, outDir := newOutput(t)
	if err := collectJournal(context.Background(), out); err != nil {
		t.Fatal(err)
	}

	evidencePath := filepath.Join(outDir, "ai/evidence.jsonl")
	assertEvidenceRecord(t, evidencePath, "facts/journal_events", map[string]any{
		"exists":         false,
		"record_subtype": "status",
		"status":         "parse_error",
		"line_number":    1,
	})
	assertFileNotContains(t, evidencePath, `"status":"empty"`)
}

func setLogTestHooks(root string) func() {
	oldFilesystemRoot := filesystemRoot
	oldJournalRunner := journalRunner
	filesystemRoot = root
	journalRunner = func(ctx context.Context, command string, args ...string) common.CommandResult {
		return common.CommandResult{Command: command, Args: args, Err: exec.ErrNotFound}
	}
	return func() {
		filesystemRoot = oldFilesystemRoot
		journalRunner = oldJournalRunner
	}
}

func setJournalRunnerForTest(runner func(context.Context, string, ...string) common.CommandResult) func() {
	oldJournalRunner := journalRunner
	journalRunner = runner
	return func() {
		journalRunner = oldJournalRunner
	}
}

func newOutput(t *testing.T) (*output.Manager, string) {
	t.Helper()
	outDir := filepath.Join(t.TempDir(), "out")
	out, err := output.New(outDir, "dual", evidence.Session{
		CaseID:    "case-test",
		HostID:    "host-test",
		SessionID: "session-test",
		CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return out, outDir
}

func writeFixtureFile(t *testing.T, path, data string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func writeFixtureBytes(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func buildUtmpRecord(t *testing.T, utType int16, pid int32, line, id, user, host string, ts time.Time) []byte {
	t.Helper()
	record := make([]byte, 384)
	binary.LittleEndian.PutUint16(record[0:2], uint16(utType))
	binary.LittleEndian.PutUint32(record[4:8], uint32(pid))
	copyCString(record[8:40], line)
	copyCString(record[40:44], id)
	copyCString(record[44:76], user)
	copyCString(record[76:332], host)
	binary.LittleEndian.PutUint32(record[336:340], 1)
	binary.LittleEndian.PutUint32(record[340:344], uint32(ts.Unix()))
	return record
}

func buildUtmpRecord400(t *testing.T, utType int16, pid int32, line, id, user, host, addr string, ts time.Time) []byte {
	t.Helper()
	record := make([]byte, 400)
	binary.LittleEndian.PutUint16(record[0:2], uint16(utType))
	binary.LittleEndian.PutUint32(record[4:8], uint32(pid))
	copyCString(record[8:40], line)
	copyCString(record[40:44], id)
	copyCString(record[44:76], user)
	copyCString(record[76:332], host)
	binary.LittleEndian.PutUint32(record[336:340], 1)
	binary.LittleEndian.PutUint64(record[344:352], uint64(ts.Unix()))
	if addr != "" {
		ip := strings.Split(addr, ".")
		if len(ip) != 4 {
			t.Fatalf("test only supports IPv4 addr, got %s", addr)
		}
		for i, part := range ip {
			value, err := strconv.Atoi(part)
			if err != nil {
				t.Fatal(err)
			}
			record[360+i] = byte(value)
		}
	}
	return record
}

func buildLastlogRecord(t *testing.T, ts time.Time, line, host string) []byte {
	t.Helper()
	record := make([]byte, 296)
	binary.LittleEndian.PutUint64(record[0:8], uint64(ts.Unix()))
	copyCString(record[8:40], line)
	copyCString(record[40:296], host)
	return record
}

func copyCString(dst []byte, value string) {
	copy(dst, []byte(value))
}

func writeGzipFixture(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(file)
	if _, err := gz.Write([]byte(data)); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func rootPath(root, sourcePath string) string {
	return filepath.Join(root, strings.TrimPrefix(filepath.Clean(sourcePath), string(filepath.Separator)))
}

func assertFileContains(t *testing.T, path, fragment string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), fragment) {
		t.Fatalf("%s does not contain %q: %s", path, fragment, string(data))
	}
}

func assertFileNotContains(t *testing.T, path, fragment string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), fragment) {
		t.Fatalf("%s unexpectedly contains %q: %s", path, fragment, string(data))
	}
}

func assertFileExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func assertJSONL(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var decoded map[string]any
		if err := json.Unmarshal([]byte(line), &decoded); err != nil {
			t.Fatalf("%s line %d is not JSON: %v\n%s", path, i+1, err, line)
		}
	}
}

func assertEvidenceRecord(t *testing.T, path, stream string, expected map[string]any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	candidates := []map[string]any{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var decoded struct {
			Stream string         `json:"stream"`
			Data   map[string]any `json:"data"`
		}
		if err := json.Unmarshal([]byte(line), &decoded); err != nil {
			t.Fatalf("%s is not valid evidence JSONL: %v\n%s", path, err, line)
		}
		if decoded.Stream != stream {
			continue
		}
		candidates = append(candidates, decoded.Data)
		if evidenceDataMatches(decoded.Data, expected) {
			return
		}
	}
	t.Fatalf("%s does not contain stream %q record matching %#v; candidates: %#v", path, stream, expected, candidates)
}

func evidenceDataMatches(data map[string]any, expected map[string]any) bool {
	for key, want := range expected {
		got, ok := data[key]
		if !ok {
			return false
		}
		switch want := want.(type) {
		case int:
			gotNumber, ok := got.(float64)
			if !ok || gotNumber != float64(want) {
				return false
			}
		default:
			if got != want {
				return false
			}
		}
	}
	return true
}
