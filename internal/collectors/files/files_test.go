package files

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"linux-dfir/internal/evidence"
	"linux-dfir/internal/output"
)

func TestCollectWithFixtureFileEnum(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	restore := setRootsForTest(root, proc)
	defer restore()

	oldHashLimit := hashSizeLimit
	hashSizeLimit = 16
	defer func() { hashSizeLimit = oldHashLimit }()

	writeFixtureFile(t, rootPath(root, "/proc/sys/kernel/osrelease"), "1.2.3\n", 0o640)
	writeFixtureFile(t, rootPath(root, "/proc/kmsg"), "stream-like-kernel-log\n", 0o640)
	writeFixtureFile(t, rootPath(root, "/lib/modules/1.2.3/kernel/drivers/test.ko"), "module-bytes\n", 0o640)
	writeFixtureFile(t, rootPath(root, "/tmp/open.log"), "abc\n", 0o640)
	writeFixtureFile(t, rootPath(root, "/tmp/recent.sh"), "#!/bin/sh\nid\n", 0o755)
	writeFixtureFile(t, rootPath(root, "/tmp/dfir-old-run/ai/evidence.jsonl"), "old evidence\n", 0o640)
	writeFixtureFile(t, rootPath(root, "/tmp/linux-dfir-review-profiles/ai/manifest.json"), "{}\n", 0o640)
	writeFixtureFile(t, rootPath(root, "/tmp/dfir-work/profiles/standard.yaml"), "name: standard\n", 0o640)
	writeFixtureFile(t, rootPath(root, "/tmp/linux-dfir-root-profiles/standard.yaml"), "name: standard\n", 0o640)
	writeFixtureFile(t, rootPath(root, "/tmp/dfir-notes.sh"), "#!/bin/sh\nwhoami\n", 0o755)
	writeFixtureFile(t, rootPath(root, "/tmp/linux-dfir-backdoor/payload.sh"), "#!/bin/sh\nid\n", 0o755)
	writeFixtureFile(t, rootPath(root, "/var/tmp/big.bin"), strings.Repeat("x", 32), 0o640)
	suidPath := rootPath(root, "/usr/bin/suidbin")
	writeFixtureFile(t, suidPath, "suid\n", os.ModeSetuid|0o755)
	suidInfo, err := os.Lstat(suidPath)
	if err != nil {
		t.Fatal(err)
	}
	if suidInfo.Mode()&os.ModeSetuid == 0 {
		t.Fatalf("fixture suid bit not set: %s", suidInfo.Mode().String())
	}
	writeFixtureFile(t, rootPath(root, "/etc/crontab"), "* * * * * root /tmp/recent.sh\n", 0o640)
	writeFixtureFile(t, rootPath(root, "/etc/systemd/system/demo.service"), "[Service]\nExecStart=/tmp/recent.sh\n", 0o640)
	if err := os.Symlink("/outside/escape", rootPath(root, "/tmp/link-out")); err != nil {
		t.Fatal(err)
	}

	procBase := filepath.Join(proc, "123")
	writeFixtureFile(t, filepath.Join(procBase, "status"), "Name:\topenproc\nUid:\t1000\t1000\t1000\t1000\n", 0o640)
	if err := os.MkdirAll(filepath.Join(procBase, "fd"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/bin/suidbin", filepath.Join(procBase, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/tmp", filepath.Join(procBase, "cwd")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/tmp/open.log", filepath.Join(procBase, "fd", "7")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/proc/kmsg", filepath.Join(procBase, "fd", "10")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/tmp/dfir-work/profiles/standard.yaml", filepath.Join(procBase, "fd", "11")); err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, filepath.Join(procBase, "fd", "8"), "not-a-symlink\n", 0o640)
	if err := os.Symlink("/tmp/deleted.log (deleted)", filepath.Join(procBase, "fd", "9")); err != nil {
		t.Fatal(err)
	}
	procRace := filepath.Join(proc, "124")
	writeFixtureFile(t, filepath.Join(procRace, "status"), "Name:\trace\nUid:\t1000\t1000\t1000\t1000\n", 0o640)

	out, outDir := newOutput(t)
	if err := Collect(context.Background(), out); err != nil {
		t.Fatal(err)
	}

	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "/lib/modules/1.2.3/kernel/drivers/test.ko")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "/tmp/link-out")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"link_target":"/outside/escape"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "/tmp/open.log")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "/tmp/deleted.log (deleted)")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"exists":false`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"process_pid":123`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"process_fd":"7"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "/tmp/recent.sh")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "/tmp/open.log")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "/tmp/dfir-notes.sh")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "/tmp/linux-dfir-backdoor/payload.sh")
	assertFileNotContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "/tmp/dfir-old-run/ai/evidence.jsonl")
	assertFileNotContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "/tmp/linux-dfir-review-profiles/ai/manifest.json")
	assertFileNotContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "/tmp/dfir-work/profiles/standard.yaml")
	assertFileNotContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "/tmp/linux-dfir-root-profiles/standard.yaml")
	assertFileNotContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "0001-01-01T00:00:00Z")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"sha256":"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "/proc/kmsg")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"skip_reason":"pseudo filesystem path is metadata-only"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "/var/tmp/big.bin")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"skipped":true`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "deleted_open_file")
	assertFileContains(t, filepath.Join(outDir, "legacy/enum/enum_file.out"), "/tmp/open.log")
	assertFileContains(t, filepath.Join(outDir, "legacy/enum/file_info.out"), "/usr/bin/suidbin")
	assertFileContains(t, filepath.Join(outDir, "legacy/enum/file_hashes.out"), "/tmp/open.log")
}

func TestWriteClassifiedSUIDRecord(t *testing.T) {
	out, outDir := newOutput(t)
	record := FileRecord{
		RecordMeta: out.Meta(collector, filesRel, "/usr/bin/suidbin", "file", "high"),
		Exists:     true,
		Path:       "/usr/bin/suidbin",
		Category:   "suid_scan",
		FileType:   "regular",
		Mode:       "-rwsr-xr-x",
		SUID:       true,
	}
	if err := writeClassifiedRecords(out, record); err != nil {
		t.Fatal(err)
	}
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "/usr/bin/suidbin")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"suid":true`)
}

func TestCollectWithMissingRootsWritesAbsent(t *testing.T) {
	root := t.TempDir()
	restore := setRootsForTest(root, filepath.Join(root, "missing-proc"))
	defer restore()

	out, outDir := newOutput(t)
	if err := Collect(context.Background(), out); err != nil {
		t.Fatal(err)
	}

	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"exists":false`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"exists":false`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "missing-proc")
	assertFileContains(t, filepath.Join(outDir, "legacy/enum/enum_file.out"), "")
	assertFileContains(t, filepath.Join(outDir, "legacy/enum/file_info.out"), "path\tcategory")
}

func setRootsForTest(fsRoot, proc string) func() {
	oldFilesystemRoot := filesystemRoot
	oldProcRoot := procRoot
	oldHashLimit := hashSizeLimit
	oldScanLimit := scanFileLimit
	oldRecentLimit := recentFileLimit
	filesystemRoot = fsRoot
	procRoot = proc
	hashSizeLimit = int64(maxHashBytes)
	scanFileLimit = maxScanFiles
	recentFileLimit = maxRecentFiles
	return func() {
		filesystemRoot = oldFilesystemRoot
		procRoot = oldProcRoot
		hashSizeLimit = oldHashLimit
		scanFileLimit = oldScanLimit
		recentFileLimit = oldRecentLimit
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
