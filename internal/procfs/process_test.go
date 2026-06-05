package procfs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadProcess(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "123")
	writeFile(t, filepath.Join(base, "status"), "Name:\ttestproc\nState:\tS (sleeping)\nPPid:\t1\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n")
	writeFile(t, filepath.Join(base, "cmdline"), "testproc\x00--flag\x00")
	writeFile(t, filepath.Join(base, "environ"), "PATH=/bin\x00SECRET_TOKEN=abc\x00")
	writeFile(t, filepath.Join(base, "maps"), "00400000-00401000 r-xp 00000000 00:00 0 /bin/test\n00401000-00402000 rwxp 00000000 00:00 0 /tmp/deleted (deleted)\n")
	if err := os.MkdirAll(filepath.Join(base, "fd"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/bin/test", filepath.Join(base, "exe")); err != nil {
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
	if err := os.Symlink("socket:[42]", filepath.Join(base, "fd", "2")); err != nil {
		t.Fatal(err)
	}

	proc, err := ReadProcess(root, 123)
	if err != nil {
		t.Fatal(err)
	}
	if proc.Name != "testproc" || proc.PPID != 1 || proc.UID != 1000 || proc.GID != 1000 {
		t.Fatalf("unexpected process: %+v", proc)
	}
	if len(proc.Cmdline) != 2 || proc.Cmdline[1] != "--flag" {
		t.Fatalf("unexpected cmdline: %+v", proc.Cmdline)
	}
	envSummary := SummarizeEnviron(proc.Environ)
	if len(envSummary.RedactedKeys) != 1 || envSummary.RedactedKeys[0] != "SECRET_TOKEN" {
		t.Fatalf("secret env not redacted: %+v", envSummary)
	}
	if len(proc.FDs) != 2 || proc.FDs[1].Type != "socket" {
		t.Fatalf("unexpected fds: %+v", proc.FDs)
	}
	if proc.Maps.Count != 2 || proc.Maps.Bytes == 0 || proc.Maps.WritableExecutableCount != 1 || proc.Maps.DeletedCount != 1 {
		t.Fatalf("unexpected maps summary: %+v", proc.Maps)
	}
	if proc.Exe != "/bin/test" || proc.Cwd != "/tmp" || proc.Root != "/" {
		t.Fatalf("unexpected process links: exe=%q cwd=%q root=%q", proc.Exe, proc.Cwd, proc.Root)
	}
	if len(proc.Issues) != 0 {
		t.Fatalf("unexpected read issues: %+v", proc.Issues)
	}
}

func TestReadProcessRecordsOptionalReadIssues(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "124")
	writeFile(t, filepath.Join(base, "status"), "Name:\tpartial\nState:\tR (running)\nPPid:\t1\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n")

	proc, err := ReadProcess(root, 124)
	if err != nil {
		t.Fatal(err)
	}
	if len(proc.Issues) == 0 {
		t.Fatal("expected optional read issues")
	}
	if !hasIssue(proc.Issues, "maps") || !hasIssue(proc.Issues, "fd") {
		t.Fatalf("expected maps/fd issues, got %+v", proc.Issues)
	}
}

func TestFDType(t *testing.T) {
	if FDType("socket:[1]") != "socket" || FDType("pipe:[1]") != "pipe" || FDType("/tmp/a") != "file" {
		t.Fatal("fd type mismatch")
	}
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

func hasIssue(issues []ReadIssue, kind string) bool {
	for _, issue := range issues {
		if issue.Kind == kind {
			return true
		}
	}
	return false
}
