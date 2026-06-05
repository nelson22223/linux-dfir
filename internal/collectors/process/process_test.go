package process

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"linux-dfir/internal/evidence"
	"linux-dfir/internal/output"
	"linux-dfir/internal/procfs"
)

func TestCollectWithFixtureProc(t *testing.T) {
	root := t.TempDir()
	restore := SetProcRootForTest(filepath.Join(root, "proc"))
	defer restore()

	exePath := filepath.Join(root, "fixture-exe")
	exeData := []byte("fixture exe\n")
	if err := os.WriteFile(exePath, exeData, 0o755); err != nil {
		t.Fatal(err)
	}
	exeSHA256 := fmt.Sprintf("%x", sha256.Sum256(exeData))

	base := filepath.Join(procRoot, "123")
	writeFile(t, filepath.Join(base, "status"), "Name:\ttestproc\nState:\tS (sleeping)\nPPid:\t1\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n")
	writeFile(t, filepath.Join(base, "stat"), "123 (testproc) S 1 120 80 34816 0 0 0 0 0 0 0 0 0 0 20 0 1 0 123456\n")
	writeFile(t, filepath.Join(base, "cmdline"), "testproc\x00--flag\x00--api-key\x00super-secret-process\x00--password=\"correct horse\"\x00")
	writeFile(t, filepath.Join(base, "environ"), "SECRET_TOKEN=abc\x00")
	writeFile(t, filepath.Join(base, "maps"), "00400000-00401000 r-xp 00000000 00:00 0 /bin/test\n00401000-00402000 rwxp 00000000 00:00 0 /tmp/deleted (deleted)\n")
	if err := os.MkdirAll(filepath.Join(base, "fd"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(exePath, filepath.Join(base, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/tmp", filepath.Join(base, "cwd")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/", filepath.Join(base, "root")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/tmp/file", filepath.Join(base, "fd", "1")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/pts/3", filepath.Join(base, "fd", "0")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(base, "cgroup"), "0::/user.slice/user-1000.slice/session-2.scope\n9:cpu,memory:/docker/containerid\n")
	if err := os.MkdirAll(filepath.Join(base, "ns"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("mnt:[4026531840]", filepath.Join(base, "ns", "mnt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("pid:[4026531836]", filepath.Join(base, "ns", "pid")); err != nil {
		t.Fatal(err)
	}

	childBase := filepath.Join(procRoot, "124")
	writeFile(t, filepath.Join(childBase, "status"), "Name:\tchildproc\nState:\tR (running)\nPPid:\t123\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n")
	writeFile(t, filepath.Join(childBase, "stat"), "124 (childproc) R 123 120 80 34816 0 0 0 0 0 0 0 0 0 0 20 0 1 0 123999\n")
	writeFile(t, filepath.Join(childBase, "cmdline"), "childproc\x00--token=child-secret\x00")
	writeFile(t, filepath.Join(childBase, "environ"), "")
	writeFile(t, filepath.Join(childBase, "maps"), "")
	if err := os.MkdirAll(filepath.Join(childBase, "fd"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(exePath, filepath.Join(childBase, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/tmp", filepath.Join(childBase, "cwd")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/", filepath.Join(childBase, "root")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(childBase, "cgroup"), "0::/user.slice/user-1000.slice/session-2.scope\n")
	if err := os.MkdirAll(filepath.Join(childBase, "ns"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("mnt:[4026531840]", filepath.Join(childBase, "ns", "mnt")); err != nil {
		t.Fatal(err)
	}

	out, outDir := newOutput(t)
	if err := Collect(context.Background(), out); err != nil {
		t.Fatal(err)
	}

	assertFileContains(t, filepath.Join(outDir, "legacy/process/procfs_ps_auxw.out"), "testproc --flag")
	assertFileContains(t, filepath.Join(outDir, "legacy/process/procfs_ps_-elf.out"), "testproc --flag")
	assertFileContains(t, filepath.Join(outDir, "legacy/process/procfs_lsof.out"), "/tmp/file")
	assertFileContains(t, filepath.Join(outDir, "legacy/process/procfs_lsof.out"), "txt REG "+exePath)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"pid\":123")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"cmdline":["testproc","--flag","--api-key","[redacted]","--password=\"[redacted]\""]`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"exists\":true")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "SECRET_TOKEN")
	assertFileNotContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "abc")
	assertFileNotContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "super-secret-process")
	assertFileNotContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "correct horse")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"target\":\"/tmp/file\"")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"map_count\":2")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"writable_executable_count\":1")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "process:123")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"stream":"facts/process_lineage"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"process_name":"testproc"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"start_time_ticks":123456`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"process_session_id":80`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"tty_nr":34816`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"terminal_hint":"/dev/pts/3"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"cgroup_lines":[`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"controllers":["cpu","memory"]`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"namespaces":[`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"inode":"4026531840"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"exe_sha256":"`+exeSHA256+`"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"exe_size":12`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"lineage_key":"pid:123:start_ticks:123456"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"parent_key":"pid:123:start_ticks:123456"`)
	assertStreamCount(t, filepath.Join(outDir, "ai/evidence.jsonl"), "entities/process", 2)
	assertStreamCount(t, filepath.Join(outDir, "ai/evidence.jsonl"), "facts/process_lineage", 2)
	assertStreamCount(t, filepath.Join(outDir, "ai/evidence.jsonl"), "parsed/process_fds", 0)
	assertStreamCount(t, filepath.Join(outDir, "ai/evidence.jsonl"), "parsed/process_maps", 0)
	assertEvidenceLineContainsAll(t, filepath.Join(outDir, "ai/evidence.jsonl"), []string{`"stream":"entities/process"`, `"pid":123`}, []string{`"fds":[`, `"maps":`, `"sources":[`})
	assertEvidenceLineContainsAll(t, filepath.Join(outDir, "ai/evidence.jsonl"), []string{`"stream":"facts/process_lineage"`, `"pid":124`}, []string{`"ppid":123`, `"parent_key":"pid:123:start_ticks:123456"`, `"cmdline":["childproc","--token=[redacted]"]`})
}

func TestProcessLineageHashesProcExeLinkTarget(t *testing.T) {
	root := t.TempDir()
	restore := SetProcRootForTest(filepath.Join(root, "proc"))
	defer restore()

	runningExe := filepath.Join(root, "running-exe")
	runningData := []byte("running image\n")
	if err := os.WriteFile(runningExe, runningData, 0o755); err != nil {
		t.Fatal(err)
	}
	replacedExe := filepath.Join(root, "replaced-exe")
	replacedData := []byte("replaced image\n")
	if err := os.WriteFile(replacedExe, replacedData, 0o755); err != nil {
		t.Fatal(err)
	}
	runningSHA256 := fmt.Sprintf("%x", sha256.Sum256(runningData))
	replacedSHA256 := fmt.Sprintf("%x", sha256.Sum256(replacedData))

	base := filepath.Join(procRoot, "222")
	writeFile(t, filepath.Join(base, "status"), "Name:\treplaced\nState:\tS (sleeping)\nPPid:\t1\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n")
	writeFile(t, filepath.Join(base, "stat"), "222 (replaced) S 1 120 80 0 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0 4444\n")
	writeFile(t, filepath.Join(base, "cmdline"), "replaced\x00")
	writeFile(t, filepath.Join(base, "environ"), "")
	writeFile(t, filepath.Join(base, "maps"), "")
	if err := os.MkdirAll(filepath.Join(base, "fd"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(base, "ns"), 0o750); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(base, "cgroup"), "")
	if err := os.Symlink(runningExe, filepath.Join(base, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/tmp", filepath.Join(base, "cwd")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/", filepath.Join(base, "root")); err != nil {
		t.Fatal(err)
	}

	proc, err := procfs.ReadProcess(procRoot, 222)
	if err != nil {
		t.Fatal(err)
	}
	proc.Exe = replacedExe
	out, _ := newOutput(t)
	record, issues := processLineageRecord(out, proc, map[int]string{222: lineageKey(proc)})
	if len(issues) != 0 {
		t.Fatalf("unexpected issues: %+v", issues)
	}
	if record.Exe != replacedExe {
		t.Fatalf("display exe should preserve readlink text, got %q", record.Exe)
	}
	if record.ExeSHA256 != runningSHA256 {
		t.Fatalf("exe hash should use proc exe link target, got %s want %s", record.ExeSHA256, runningSHA256)
	}
	if record.ExeSHA256 == replacedSHA256 {
		t.Fatalf("exe hash used replaced path instead of proc exe link")
	}
}

func TestCollectHandlesPidRace(t *testing.T) {
	root := t.TempDir()
	restore := SetProcRootForTest(filepath.Join(root, "proc"))
	defer restore()

	if err := os.MkdirAll(filepath.Join(procRoot, "321"), 0o750); err != nil {
		t.Fatal(err)
	}
	out, outDir := newOutput(t)
	if err := Collect(context.Background(), out); err != nil {
		t.Fatal(err)
	}
	assertEvidenceNotContainsIfExists(t, filepath.Join(outDir, "ai/evidence.jsonl"), "pid race")
	assertFileContains(t, filepath.Join(outDir, "legacy/process/procfs_ps_auxw.out"), "COMMAND")
}

func TestCollectRecordsFDEntryReadErrors(t *testing.T) {
	root := t.TempDir()
	restore := SetProcRootForTest(filepath.Join(root, "proc"))
	defer restore()

	base := filepath.Join(procRoot, "456")
	writeFile(t, filepath.Join(base, "status"), "Name:\tfderr\nState:\tS (sleeping)\nPPid:\t1\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n")
	writeFile(t, filepath.Join(base, "cmdline"), "fderr\x00")
	writeFile(t, filepath.Join(base, "environ"), "")
	writeFile(t, filepath.Join(base, "maps"), "")
	if err := os.MkdirAll(filepath.Join(base, "fd"), 0o750); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(base, "fd", "9"), "not-a-symlink")

	out, outDir := newOutput(t)
	if err := Collect(context.Background(), out); err != nil {
		t.Fatal(err)
	}
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"fd\":\"9\"")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"exists\":false")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "/fd/9")
}

func TestCollectWithMissingProcWritesAbsent(t *testing.T) {
	root := t.TempDir()
	restore := SetProcRootForTest(filepath.Join(root, "missing-proc"))
	defer restore()

	out, outDir := newOutput(t)
	if err := Collect(context.Background(), out); err != nil {
		t.Fatal(err)
	}
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "absent")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"exists\":false")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"exists\":false")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "missing-proc")
	assertFileContains(t, filepath.Join(outDir, "legacy/process/procfs_ps_auxw.out"), "COMMAND")
	assertFileContains(t, filepath.Join(outDir, "legacy/process/procfs_lsof.out"), "COMMAND PID")
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

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o640); err != nil {
		t.Fatal(err)
	}
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

func assertEvidenceNotContainsIfExists(t *testing.T, path, fragment string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), fragment) {
		t.Fatalf("%s unexpectedly contains %q: %s", path, fragment, string(data))
	}
}

func assertStreamCount(t *testing.T, path, stream string, want int) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := 0
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var record struct {
			Stream string `json:"stream"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("invalid evidence line: %v: %s", err, line)
		}
		if record.Stream == stream {
			got++
		}
	}
	if got != want {
		t.Fatalf("stream %s count=%d want=%d", stream, got, want)
	}
}

func assertEvidenceLineContainsAll(t *testing.T, path string, requiredLineFragments []string, expectedFragments []string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		matched := true
		for _, fragment := range requiredLineFragments {
			if !strings.Contains(line, fragment) {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}
		for _, fragment := range expectedFragments {
			if !strings.Contains(line, fragment) {
				t.Fatalf("matched evidence line missing %q: %s", fragment, line)
			}
		}
		return
	}
	t.Fatalf("no evidence line matched required fragments: %v", requiredLineFragments)
}
