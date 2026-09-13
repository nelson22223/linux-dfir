package ddeirootkit

import (
	"os"
	"path/filepath"
	"testing"
)

// fixture builds a fake root tree for a test case.
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

// withELF swaps the ELF inspector seam for the duration of a test.
func withELF(t *testing.T, fake func(path string) elfFacts) {
	t.Helper()
	old := inspectELF
	inspectELF = fake
	t.Cleanup(func() { inspectELF = old })
}

func opts(root string) Options {
	return Options{Root: root, SelfPID: 999999, ScanProcMaps: true}
}

func TestCleanHostNoPreload(t *testing.T) {
	root := fixture(t, map[string]string{"etc/hostname": "cleanhost"})
	rep := Run(opts(root))
	if rep.Verdict != VerdictClean {
		t.Fatalf("expected CLEAN, got %s (%+v)", rep.Verdict, rep.Findings)
	}
}

func TestPreloadFamilyHash(t *testing.T) {
	root := fixture(t, map[string]string{
		"etc/ld.so.preload": "/usr/lib64/libnet.so\n",
		"usr/lib64/libnet.so": "placeholder", // hash won't match; use hook symbols below
	})
	withELF(t, func(path string) elfFacts {
		return elfFacts{IsELF: true, DefinedHooks: 6, DefinedTotal: 17}
	})
	rep := Run(opts(root))
	if rep.Verdict != VerdictInfected {
		t.Fatalf("expected INFECTED via hook symbols, got %s (%+v)", rep.Verdict, rep.Findings)
	}
}

// TestLegitLibnetDevelNotFlagged is the key false-positive guard: a real
// libnet-devel /usr/lib64/libnet.so defines libnet_* only, imports stat.
func TestLegitLibnetDevelNotFlagged(t *testing.T) {
	root := fixture(t, map[string]string{
		"usr/lib64/libnet.so": "legit packet library bytes",
	})
	withELF(t, func(path string) elfFacts {
		return elfFacts{IsELF: true, DefinedHooks: 0, DefinedTotal: 40}
	})
	rep := Run(opts(root))
	if rep.Verdict != VerdictClean {
		t.Fatalf("legit libnet.so on disk (not preloaded) must stay CLEAN, got %s (%+v)", rep.Verdict, rep.Findings)
	}
}

// A preloaded legitimate helper library (defines its own namespace only) must
// land in REVIEW, not INFECTED.
func TestPreloadLegitLibraryIsReview(t *testing.T) {
	root := fixture(t, map[string]string{
		"etc/ld.so.preload":      "/usr/lib64/libesmtp.so",
		"usr/lib64/libesmtp.so":  "legit helper",
	})
	withELF(t, func(path string) elfFacts {
		return elfFacts{IsELF: true, DefinedHooks: 0, DefinedTotal: 25}
	})
	rep := Run(opts(root))
	if rep.Verdict != VerdictReview {
		t.Fatalf("expected REVIEW for unexpected-but-benign preload entry, got %s (%+v)", rep.Verdict, rep.Findings)
	}
}

func TestPreloadBrokenEntryIsReview(t *testing.T) {
	root := fixture(t, map[string]string{
		"etc/ld.so.preload": "/usr/lib64/does-not-exist.so\n",
	})
	rep := Run(opts(root))
	if rep.Verdict != VerdictReview {
		t.Fatalf("expected REVIEW for broken entry, got %s", rep.Verdict)
	}
}

// Renamed family variant still fires: preload references an innocent-looking
// name, but the ELF defines the hook symbol set.
func TestRenamedVariantStillFires(t *testing.T) {
	root := fixture(t, map[string]string{
		"etc/ld.so.preload":      "/usr/lib64/libsystemd_private.so",
		"usr/lib64/libsystemd_private.so": "renamed hook lib",
	})
	withELF(t, func(path string) elfFacts {
		return elfFacts{IsELF: true, DefinedHooks: 4, DefinedTotal: 12}
	})
	rep := Run(opts(root))
	if rep.Verdict != VerdictInfected {
		t.Fatalf("renamed variant must fire, got %s (%+v)", rep.Verdict, rep.Findings)
	}
}

func TestXinetdStaticReplacement(t *testing.T) {
	root := fixture(t, map[string]string{
		"usr/sbin/xinetd": "static pie bytes",
	})
	withELF(t, func(path string) elfFacts {
		return elfFacts{IsELF: true, HasInterpreter: false, DefinedHooks: 0}
	})
	rep := Run(opts(root))
	if rep.Verdict != VerdictInfected {
		t.Fatalf("static xinetd must be INFECTED, got %s (%+v)", rep.Verdict, rep.Findings)
	}
}

func TestXinetdStockDynamicClean(t *testing.T) {
	root := fixture(t, map[string]string{
		"usr/sbin/xinetd": "dynamic xinetd bytes",
	})
	withELF(t, func(path string) elfFacts {
		return elfFacts{IsELF: true, HasInterpreter: true, DefinedHooks: 0}
	})
	rep := Run(opts(root))
	if rep.Verdict != VerdictClean {
		t.Fatalf("stock dynamic xinetd must stay CLEAN, got %s (%+v)", rep.Verdict, rep.Findings)
	}
}

func TestMarkerSignTxtRequiresHex64(t *testing.T) {
	hexRoot := fixture(t, map[string]string{
		"root/sign.txt": "ec2d99096b958b06221c981d1e9262a3f84b9ccb9e6d496e9c3e11735383d73f",
	})
	if rep := Run(opts(hexRoot)); rep.Verdict != VerdictInfected {
		t.Fatalf("64-hex sign.txt must be INFECTED, got %s", rep.Verdict)
	}
	benignRoot := fixture(t, map[string]string{
		"root/sign.txt": "deployment signed by ops team",
	})
	if rep := Run(opts(benignRoot)); rep.Verdict != VerdictClean {
		t.Fatalf("non-hex sign.txt must not be decisive, got %s (%+v)", rep.Verdict, rep.Findings)
	}
}

func TestMarkerDirs(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "media", "vbccsb"), 0o755); err != nil {
		t.Fatal(err)
	}
	rep := Run(opts(root))
	if rep.Verdict != VerdictInfected {
		t.Fatalf("marker dir must be INFECTED, got %s", rep.Verdict)
	}
}

func TestExitCodes(t *testing.T) {
	cases := map[Verdict]int{VerdictClean: 0, VerdictReview: 1, VerdictInfected: 3}
	for v, want := range cases {
		if got := ExitCode(v); got != want {
			t.Fatalf("ExitCode(%s)=%d want %d", v, got, want)
		}
	}
}

func TestWriteLogCreatesFile(t *testing.T) {
	root := fixture(t, map[string]string{
		"etc/ld.so.preload": "/usr/lib64/libnet.so\n",
		"usr/lib64/libnet.so": "x",
	})
	withELF(t, func(path string) elfFacts {
		return elfFacts{IsELF: true, DefinedHooks: 5, DefinedTotal: 17}
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
	if len(data) == 0 || data[0] != '#' {
		t.Fatalf("unexpected log content: %q", data[:min(20, len(data))])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
