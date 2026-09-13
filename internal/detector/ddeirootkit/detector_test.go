package ddeirootkit

import (
	"os"
	"path/filepath"
	"testing"
)

// fixture builds a minimal fake root tree for a test case.
func fixture(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func opts(root string) Options {
	return Options{Root: root, SelfPID: 999999, ScanProcMaps: true, ScanLogTraces: true}
}

func TestCleanHost(t *testing.T) {
	root := fixture(t, map[string]string{
		"etc/hostname": "cleanhost",
	})
	rep := Run(opts(root))
	if rep.Verdict != VerdictClean {
		t.Fatalf("expected CLEAN, got %s (%+v)", rep.Verdict, rep.Checks)
	}
}

func TestPreloadFamilyEntry(t *testing.T) {
	root := fixture(t, map[string]string{
		"etc/ld.so.preload": "/usr/lib64/libnet.so\n",
	})
	rep := Run(opts(root))
	if rep.Verdict != VerdictInfected {
		t.Fatalf("expected INFECTED, got %s", rep.Verdict)
	}
	found := false
	for _, c := range rep.Checks {
		if c.ID == "preload_entry" && c.Severity == SeverityConfirmed {
			found = true
		}
	}
	if !found {
		t.Fatal("missing confirmed preload_entry check")
	}
}

func TestMarkerFiles(t *testing.T) {
	root := fixture(t, map[string]string{
		"root/sign.txt": "ec2d99096b958b06221c981d1e9262a3f84b9ccb9e6d496e9c3e11735383d73f",
	})
	rep := Run(opts(root))
	if rep.Verdict != VerdictInfected {
		t.Fatalf("expected INFECTED via marker, got %s", rep.Verdict)
	}
}

func TestUnexpectedPreloadEntryIsHigh(t *testing.T) {
	root := fixture(t, map[string]string{
		"etc/ld.so.preload": "/usr/local/lib/watchdog.so\n",
	})
	rep := Run(opts(root))
	if rep.Verdict != VerdictSuspicious {
		t.Fatalf("expected SUSPICIOUS for single high indicator, got %s", rep.Verdict)
	}
}

func TestLogTraceFires(t *testing.T) {
	root := fixture(t, map[string]string{
		"var/log/messages": "Sep 11 00:01:40 host network: ERROR: ld.so: object '/usr/lib64/libnet.so' from /etc/ld.so.preload cannot be preloaded: ignored.\n",
	})
	rep := Run(opts(root))
	hit := false
	for _, c := range rep.Checks {
		if c.ID == "log_traces" && c.Severity == SeverityMedium {
			hit = true
		}
	}
	if !hit {
		t.Fatal("expected medium log_traces check")
	}
	// log trace alone (one medium) must stay clean/suspicious-free.
	if rep.Verdict != VerdictClean {
		t.Fatalf("single medium should not trip verdict, got %s", rep.Verdict)
	}
}

func TestWriteLogCreatesFile(t *testing.T) {
	root := fixture(t, map[string]string{
		"etc/ld.so.preload": "/usr/lib64/libnet.so\n",
	})
	rep := Run(opts(root))
	dir := t.TempDir()
	path, err := WriteLog(rep, dir)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path)[:0] != "" || len(data) == 0 {
		t.Fatal("log file empty")
	}
	if string(data[:1]) != "#" {
		t.Fatalf("unexpected log preamble: %q", data[:1])
	}
}
